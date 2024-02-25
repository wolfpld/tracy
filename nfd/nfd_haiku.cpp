#include "nfd.h"

#include <FilePanel.h>
#include <Window.h>
#include <Path.h>
#include <string.h>

nfdresult_t NFD_Init(void) {
	return NFD_OKAY;
}

void NFD_Quit(void) {}

static nfdresult_t dialog(BFilePanel &p, nfdnchar_t **outPath,
                          const nfdnfilteritem_t *filterList,
                          nfdfiltersize_t filterCount) {
	p.Show();
	while (p.IsShowing())
		usleep(100000);
	entry_ref sel;
	if (p.GetNextSelectedRef(&sel) == B_OK) {
		BEntry e(&sel);
		BPath path;
		if (e.GetPath(&path) == B_OK) {
			outPath[0] = strdup(path.Path());
			return NFD_OKAY;
		}
	}
	return NFD_CANCEL;
}

class NFDFilter : public BRefFilter {
public:
	NFDFilter(const nfdnfilteritem_t *filterList, nfdfiltersize_t filterCount) {}

	bool Filter(const entry_ref *ref, BNode *node, struct stat_beos *stat,
				const char *mimeType) override {
		return true;
	}
};

nfdresult_t
NFD_OpenDialogN(nfdnchar_t **outPath, const nfdnfilteritem_t *filterList,
                nfdfiltersize_t filterCount, const nfdnchar_t *defaultPath) {
	NFDFilter f(filterList, filterCount);
	BFilePanel p(B_OPEN_PANEL, NULL, NULL, 0, false, NULL, &f, true, true);
	p.Window()->SetTitle(filterList[0].name);
	if (defaultPath)
		p.SetPanelDirectory(defaultPath);
	return dialog(p, outPath, filterList, filterCount);
}

nfdresult_t NFD_SaveDialogN(nfdnchar_t** outPath,
							const nfdnfilteritem_t* filterList,
							nfdfiltersize_t filterCount,
							const nfdnchar_t* defaultPath,
							const nfdnchar_t* defaultName) {
	NFDFilter f(filterList, filterCount);	
	BFilePanel p(B_SAVE_PANEL, NULL, NULL, 0, false, NULL, &f, true, true);
	p.Window()->SetTitle(filterList[0].name);
	if (defaultPath)
		p.SetPanelDirectory(defaultPath);
	if (defaultName)
		p.SetSaveText(defaultName);
	return dialog(p, outPath, filterList, filterCount);
}

void NFD_FreePathN(nfdnchar_t* filePath) {
    free(filePath);
}
