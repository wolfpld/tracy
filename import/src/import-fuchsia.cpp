#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <ostream>
#include <utility>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

#include <fstream>
#include <sstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
#include <variant>

#include <sys/stat.h>

#ifdef _MSC_VER
#define stat64 _stat64
#endif
#if defined __APPLE__
#define stat64 stat
#endif

#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMmap.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../zstd/zstd.h"

void Usage() {
  printf("Usage: import-fuchsia input.json output.tracy\n\n");
  printf("See: "
         "https://fuchsia.dev/fuchsia-src/reference/tracing/trace-format\n\n");
  exit(1);
}

#define ROUND_TO_WORD(n) ((n) + ((~((n)-1)) & 0x7))

struct ThreadRef {
  uint64_t pid;
  uint64_t tid;
};

inline bool operator==(const ThreadRef t1, const ThreadRef t2) {
  return t1.pid == t2.pid && t1.tid == t2.tid;
}

struct Unit {};

// arguments
using ArgumentValue =
    std::variant<uint64_t, int64_t, double, bool, Unit, std::string>;

struct Argument {
  std::string name;
  ArgumentValue value;
};

// encode a pair of "real pid, real tid" from a trace into a
// pseudo thread ID living in the single namespace of Tracy threads.
struct PidTidEncoder {
  ThreadRef thref;
  uint64_t pseudo_tid; // fake thread id, unique within Tracy
};

// A span into the main buffer
struct Record {
  const uint64_t *p;
  uint16_t len_word;
  uint64_t header;
};

struct DecodeState {
  std::vector<PidTidEncoder> tid_encoders;
  std::unordered_map<uint64_t, std::string> threadNames;
  // compressed thread refs
  std::unordered_map<uint16_t, ThreadRef> threadRefs;
  // compressed strings
  std::unordered_map<uint16_t, std::string> stringRefs;
};

// Append a string representation of `val` to `res`
void appendArgumentValue(std::string &res, ArgumentValue &val) {
  char buf[32];
  buf[31] = 0;
  if (std::holds_alternative<std::string>(val)) {
    res += std::get<std::string>(val);
  } else if (std::holds_alternative<uint64_t>(val)) {
    snprintf(buf, 31, "%" PRIu64, std::get<uint64_t>(val));
    res.append(buf);
  } else if (std::holds_alternative<int64_t>(val)) {
    snprintf(buf, 31, "%" PRId64, std::get<int64_t>(val));
    res.append(buf);
  } else if (std::holds_alternative<bool>(val)) {
    res += std::get<bool>(val) ? "true" : "false";
  } else if (std::holds_alternative<double>(val)) {
    snprintf(buf, 31, "%.5f", std::get<double>(val));
    res += buf;
  }
}

// Read input into a local buffer
std::vector<uint8_t> read_input(const char *input) {
  std::vector<uint8_t> buf;

  FILE *f = fopen(input, "rb");
  if (!f) {
    fprintf(stderr, "Cannot open input file!\n");
    exit(1);
  }
  struct stat64 sb;
  if (stat64(input, &sb) != 0) {
    fprintf(stderr, "Cannot open input file!\n");
    fclose(f);
    exit(1);
  }

  const auto zsz = sb.st_size;
  auto zbuf = (char *)mmap(nullptr, zsz, PROT_READ, MAP_SHARED, fileno(f), 0);
  fclose(f);
  if (!zbuf) {
    fprintf(stderr, "Cannot mmap input file!\n");
    exit(1);
  }

  const auto fnsz = strlen(input);
  if (fnsz > 4 && memcmp(input + fnsz - 4, ".zst", 4) == 0) {

    auto zctx = ZSTD_createDStream();
    ZSTD_initDStream(zctx);

    enum { tmpSize = 64 * 1024 };
    auto tmp = new char[tmpSize];

    ZSTD_inBuffer_s zin = {zbuf, (size_t)zsz};
    ZSTD_outBuffer_s zout = {tmp, (size_t)tmpSize};

    buf.reserve(1024 * 1024);

    while (zin.pos < zin.size) {
      const auto res = ZSTD_decompressStream(zctx, &zout, &zin);
      if (ZSTD_isError(res)) {
        ZSTD_freeDStream(zctx);
        delete[] tmp;
        fprintf(stderr, "Couldn't decompress input file (%s)!\n",
                ZSTD_getErrorName(res));
        exit(1);
      }
      if (zout.pos > 0) {
        const auto bsz = buf.size();
        buf.resize(bsz + zout.pos);
        memcpy(buf.data() + bsz, tmp, zout.pos);
        zout.pos = 0;
      }
    }

    ZSTD_freeDStream(zctx);
    delete[] tmp;
  } else {
    // just copy to memory
    buf.resize(zsz);
    memcpy(buf.data(), zbuf, zsz);
  }

  munmap(zbuf, zsz);
  return buf;
}

// read next record starting at `offset`. Returns
// either `(ok, r)` for an in-bound record, or `(false, …)` otherwise.
std::pair<bool, Record> read_next_record(std::vector<uint8_t> const &input, size_t &offset) {

  // bound check
#define CHECK_BOUND(n) if ((n) > input.size()) { \
  fprintf(stderr, "warning: invalid record at offset %" PRIu64 "\n", offset); \
  return std::make_pair(false,Record{}); \
}

  CHECK_BOUND(offset+8);

  uint64_t header = *((uint64_t *)&input[offset]);
  uint16_t len_word = (header >> 4) & 0xfff;

  CHECK_BOUND(offset + 8*len_word);

  Record r{(uint64_t *)&input[offset], len_word, header};
  offset += 8 * len_word;
  return std::make_pair(true, r);
}

// there might be multiple processes so we allocate a pseudo-tid
// for each pair (pid, real_tid)
uint64_t getPseudoTid(DecodeState &dec, ThreadRef th) {
  for (auto &pair : dec.tid_encoders) {
    if (pair.thref == th)
      return pair.pseudo_tid;
  }

  // not found, invent a new one
  assert(th.pid <= std::numeric_limits<uint32_t>::max());
  assert(th.tid <= std::numeric_limits<uint32_t>::max());

  const auto pseudo_tid = (th.tid & 0xFFFFFFFF) | (th.pid << 32);
  dec.tid_encoders.emplace_back(PidTidEncoder{th, pseudo_tid});
  return pseudo_tid;
}

// decode thread info from a ref
ThreadRef readThread(DecodeState &dec, Record const &r, size_t &offset,
                     uint8_t ref) {
  ThreadRef th;
  if (ref == 0) {
    // inline
    th = {r.p[offset], r.p[offset + 1]};
    offset += 2;
  } else {
    th = dec.threadRefs[ref];
  }
  return th;
}

// Read a string reference into `res`
void readString(DecodeState &dec, std::string &res, Record const &r,
                size_t &offset, uint16_t ref) {
  res.clear();
  if (ref == 0) {
  } else if ((ref & 0x8000) != 0) {
    // inline string
    size_t size_name = ref & 0x7fff;
    res.resize(size_name + 1);
    memcpy(res.data(), (uint8_t *)&r.p[offset], size_name);
    res[size_name] = 0;
    offset += ROUND_TO_WORD(size_name) >> 3;
  } else {
    res = dec.stringRefs[ref];
  }
}

// Skip string reference (just modify offset)
void skipString(size_t &offset, uint16_t ref) {
  if (ref != 0 && (ref & 0x8000) != 0) {
    size_t size = ref & 0x7fff;
    offset += ROUND_TO_WORD(size) >> 3;
  }
}

// Read a single argument
void readArgument(std::vector<Argument> &args, DecodeState &dec,
                  Record const &r, size_t &offset) {
  uint64_t header = r.p[offset];
  offset += 1;

  auto ty = (uint8_t)(header & 0xf);

  uint16_t name_ref = (header >> 16) & 0xffff;
  std::string name;
  readString(dec, name, r, offset, name_ref);

  ArgumentValue value;
  switch (ty) {
  case 0:
    value = Unit{};
    break;
  case 1: {
    int32_t i = header >> 32;
    value = (int64_t)i;
  } break;
  case 2: {
    uint32_t i = header >> 32;
    value = (int64_t)i;
  } break;
  case 3: {
    int64_t i = r.p[offset];
    offset += 1;
    value = i;
  } break;
  case 4: {
    uint64_t i = r.p[offset];
    offset += 1;
    value = i;
  } break;
  case 5: {
    double i = *((double *)&r.p[offset]);
    offset += 1;
    value = i;
  } break;
  case 6: {
    uint16_t value_ref = (header >> 32) & 0xffff;
    std::string res;
    readString(dec, res, r, offset, value_ref);
    value = res;
  } break;
  case 7:
    // pointer
  case 8: {
    // koid
    uint64_t i = r.p[offset];
    offset += 1;
    value = i;
  } break;
  case 9: {
    // bool
    bool b = (bool)((header >> 32) & 1);
    value = b;
  }

  default:
    assert(false);
  }

  args.push_back({name, value});
}

/// Read `n_args` arguments from given offset
void readArguments(std::vector<Argument> &args, DecodeState &dec, Record r,
                   size_t &offset, const int n_args) {
  args.clear();
  for (int i = 0; i < n_args; ++i)
    readArgument(args, dec, r, offset);
}

bool argumentIsNumber(Argument const &arg) {
  return std::holds_alternative<double>(arg.value) ||
         std::holds_alternative<int64_t>(arg.value) ||
         std::holds_alternative<uint64_t>(arg.value);
}

double argumentToNumber(Argument const &arg) {
  if (std::holds_alternative<double>(arg.value)) {
    return std::get<double>(arg.value);
  } else if (std::holds_alternative<int64_t>(arg.value)) {
    return static_cast<double>(std::get<int64_t>(arg.value));
  } else if (std::holds_alternative<uint64_t>(arg.value)) {
    return static_cast<double>(std::get<uint64_t>(arg.value));
  } else {
    abort();
  }
}

// text made of arguments
void printArgumentsToString(std::string &res, std::vector<Argument> &args) {
  for (auto &kv : args) {
    res += kv.name.data();
    res += ": ";
    appendArgumentValue(res, kv.value);
    res += "\n";
  }
}

// Read location for a given span
void readLoc(std::string &locFile, uint32_t &locLine,
             std::vector<Argument> const &args) {
  for (auto &kv : args) {
    if (strcmp(kv.name.data(), "loc") == 0 &&
        std::holds_alternative<std::string>(kv.value)) {
      auto loc = std::get<std::string>(kv.value);
      const auto lpos = loc.find_last_of(':');
      if (lpos == std::string::npos) {
        std::swap(loc, locFile);
      } else {
        locFile = loc.substr(0, lpos);
        locLine = atoi(loc.c_str() + lpos + 1);
      }
      break;
    }
  }
}

struct TraceNotInitialized : std::exception {};

int main(int argc, char **argv) {
#ifdef _WIN32
  if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
    AllocConsole();
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), 0x07);
  }
#endif

  tracy::FileCompression clev = tracy::FileCompression::Fast;

  if (argc != 3)
    Usage();

  const char *input = argv[1];
  const char *output = argv[2];

  printf("Loading...\r");
  fflush(stdout);

  std::vector<uint8_t> buf = read_input(input);

  printf("\33[2KParsing...\r");
  fflush(stdout);

  std::vector<tracy::Worker::ImportEventTimeline> timeline;
  std::vector<tracy::Worker::ImportEventMessages> messages;
  std::vector<tracy::Worker::ImportEventPlots> plots;
  DecodeState dec;

  size_t offset = 0;
  int n_records = 0;
  std::string name;
  std::vector<Argument> arguments;
  bool initialized = false;

#define CHECK_INIT() if (!initialized) throw TraceNotInitialized{}

  while (offset < buf.size()) {
    auto [ok, r] = read_next_record(buf, offset);
    if (!ok) break;
    n_records++;

    uint8_t ty = r.header & 0xf;

    switch (ty) {
    case 0: {
      // metadata record
        if (!initialized) {
          if (r.header == 0x0016547846040010) {
            // magic string "FxT"
            // https://fuchsia.dev/fuchsia-src/reference/tracing/trace-format#magic-number-record
            initialized = true;
          }

        }
        break;
    }
    case 1: {
      CHECK_INIT();
      break; // initialization record
    }
    case 2: {
      // string
      CHECK_INIT();
      uint16_t str_ref = (r.header >> 16) & 0xffff;
      assert((str_ref & 0x8000) == 0);
      uint16_t str_len = (r.header >> 32) & 0x7fff;

      name.resize(str_len + 1);
      memcpy(name.data(), (uint8_t *)&r.p[1], str_len);
      dec.stringRefs[str_ref] = name;
      break;
    }
    case 3: {
      // thread record
      CHECK_INIT();
      uint8_t th_ref = (r.header >> 16) & 0xff;
      uint64_t pid = r.p[1];
      uint64_t tid = r.p[2];
      ThreadRef th{pid, tid};
      dec.threadRefs[th_ref] = th;
      break;
    }
    case 4: {
      // event
      CHECK_INIT();
      uint8_t ev_ty = (r.header >> 16) & 0xf;
      uint8_t n_args = (r.header >> 20) & 0xf;

      uint64_t timestamp = r.p[1];
      size_t offset = 2;

      // decode thread info
      uint8_t th_ref = (r.header >> 24) & 0xff;
      ThreadRef th = readThread(dec, r, offset, th_ref);

      // skip category
      uint16_t cat_ref = (r.header >> 32) & 0xffff;
      skipString(offset, cat_ref);

      // decode name
      uint16_t name_ref = (r.header >> 48) & 0xffff;
      readString(dec, name, r, offset, name_ref);

      readArguments(arguments, dec, r, offset, n_args);

      std::string locFile;
      uint32_t locLine = 0;
      readLoc(locFile, locLine, arguments);

      switch (ev_ty) {
      case 0: {
        // instant
        messages.emplace_back(tracy::Worker::ImportEventMessages{
            getPseudoTid(dec, th), timestamp, name});
        break;
      }

      case 1: {
        // counter
        for (auto &kv : arguments) {
          bool plotFound = false;
          auto &metricName = kv.name;

          if (!argumentIsNumber(kv))
            continue;

          auto dataPoint = std::make_pair(timestamp, argumentToNumber(kv));

          // The input file is assumed to have only very few metrics,
          // so iterating through plots is not a problem.
          for (auto &plot : plots) {
            if (plot.name == metricName) {
              plot.data.emplace_back(dataPoint);
              plotFound = true;
              break;
            }
          }
          if (!plotFound) {
            auto formatting = tracy::PlotValueFormatting::Number;
            plots.emplace_back(tracy::Worker::ImportEventPlots{
                std::move(metricName), formatting, {dataPoint}});
          }
        }
        break;
      }

      case 2: {
        // duration begin
        std::string zoneText;
        printArgumentsToString(zoneText, arguments);
        timeline.emplace_back(tracy::Worker::ImportEventTimeline{
            getPseudoTid(dec, th), timestamp, name, std::move(zoneText), false,
            std::move(locFile), locLine});
        break;
      }

      case 3: {
        // duration end
        std::string zoneText;
        printArgumentsToString(zoneText, arguments);
        timeline.emplace_back(tracy::Worker::ImportEventTimeline{
            getPseudoTid(dec, th), timestamp, "", std::move(zoneText), true});
        break;
      }

      case 4: {
        // complete duration
        const auto ts_end = r.p[offset]; // end timestamp
        const auto tid = getPseudoTid(dec, th);
        std::string zoneText;
        printArgumentsToString(zoneText, arguments);
        timeline.emplace_back(tracy::Worker::ImportEventTimeline{
            tid, timestamp, name, std::move(zoneText), false,
            std::move(locFile), locLine});
        timeline.emplace_back(
            tracy::Worker::ImportEventTimeline{tid, ts_end, "", "", true});
        break;
      }

      default: {
      }
      }

      break;
    }

    case 7: {
      // kernel object
      CHECK_INIT();

      uint8_t ty = (r.header >> 16) & 0xff;
      uint16_t name_ref = (r.header >> 24) & 0xffff;
      uint8_t n_args = (r.header >> 40) & 0xf;
      size_t offset = 1;

      uint64_t koid = r.p[offset];
      offset++;

      readString(dec, name, r, offset, name_ref);

      readArguments(arguments, dec, r, offset, n_args);

      switch (ty) {
      case 1: {
        // process
        break;
      }

      case 2: {
        // thread
        auto real_tid = koid;

        // we need the pid as well
        uint64_t pid;
        bool foundPid = false;
        for (auto &kv : arguments) {
          if (strcmp(kv.name.data(), "process") == 0 &&
              std::holds_alternative<uint64_t>(kv.value)) {
            // koid (argument type 8) are decoded as uint64
            pid = std::get<uint64_t>(kv.value);
            foundPid = true;
            break;
          }
        }

        if (!foundPid)
          continue;

        ThreadRef th{pid, real_tid};
        const auto tid = getPseudoTid(dec, th);
        dec.threadNames[tid] = name;

        break;
      }

      default: {
      }
      }
    }

    default: {
    }
    }
  }

  printf("read %d records\n", n_records);
  fflush(stdout);

  std::stable_sort(
      timeline.begin(), timeline.end(),
      [](const auto &l, const auto &r) { return l.timestamp < r.timestamp; });
  std::stable_sort(
      messages.begin(), messages.end(),
      [](const auto &l, const auto &r) { return l.timestamp < r.timestamp; });
  for (auto &v : plots)
    std::stable_sort(
        v.data.begin(), v.data.end(),
        [](const auto &l, const auto &r) { return l.first < r.first; });

  uint64_t mts = 0;
  if (!timeline.empty()) {
    mts = timeline[0].timestamp;
  }
  if (!messages.empty()) {
    if (mts > messages[0].timestamp)
      mts = messages[0].timestamp;
  }
  for (auto &plot : plots) {
    if (mts > plot.data[0].first)
      mts = plot.data[0].first;
  }
  for (auto &v : timeline)
    v.timestamp -= mts;
  for (auto &v : messages)
    v.timestamp -= mts;
  for (auto &plot : plots) {
    for (auto &v : plot.data)
      v.first -= mts;
  }

  printf("\33[2KProcessing...\r");
  fflush(stdout);

  auto &&getFilename = [](const char *in) {
    auto out = in;
    while (*out)
      ++out;
    --out;
    while (out > in && (*out != '/' || *out != '\\'))
      out--;
    return out;
  };

  tracy::Worker worker(getFilename(output), getFilename(input), timeline,
                       messages, plots, std::move(dec.threadNames));

  auto w =
      std::unique_ptr<tracy::FileWrite>(tracy::FileWrite::Open(output, clev));
  if (!w) {
    fprintf(stderr, "Cannot open output file!\n");
    exit(1);
  }
  printf("\33[2KSaving...\r");
  fflush(stdout);
  worker.Write(*w, false);

  printf("\33[2KCleanup...\n");
  fflush(stdout);

  return 0;
}
