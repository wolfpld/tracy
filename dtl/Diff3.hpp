/**
   dtl -- Diff Template Library
   
   In short, Diff Template Library is distributed under so called "BSD license",
   
   Copyright (c) 2015 Tatsuhiko Kubo <cubicdaiya@gmail.com>
   All rights reserved.
   
   Redistribution and use in source and binary forms, with or without modification,
   are permitted provided that the following conditions are met:
   
   * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
   
   * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
   
   * Neither the name of the authors nor the names of its contributors
   may be used to endorse or promote products derived from this software 
   without specific prior written permission.
   
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/* If you use this library, you must include dtl.hpp only. */

#ifndef DTL_DIFF3_H
#define DTL_DIFF3_H

namespace dtl {
    
    /**
     * diff3 class template
     * sequence must support random_access_iterator.
     */
    template <typename elem, typename sequence = vector< elem >, typename comparator = Compare< elem > >
    class Diff3
    {
    private:
        dtl_typedefs(elem, sequence)
        sequence                           A;
        sequence                           B;
        sequence                           C;
        sequence                           S;
        Diff< elem, sequence, comparator > diff_ba;
        Diff< elem, sequence, comparator > diff_bc;
        bool                               conflict;
        elem                               csepabegin;
        elem                               csepa;
        elem                               csepaend;
    public :
        Diff3 () {}
        Diff3 (const sequence& a, 
               const sequence& b, 
               const sequence& c) : A(a), B(b), C(c), 
                                    diff_ba(b, a), diff_bc(b, c), 
                                    conflict(false) {} 
        
        ~Diff3 () {}
        
        bool isConflict () const {
            return conflict;
        }
        
        sequence getMergedSequence () const {
            return S;
        }
        
        /**
         * merge changes B and C into A
         */
        bool merge () {
            if (diff_ba.getEditDistance() == 0) {     // A == B
                if (diff_bc.getEditDistance() == 0) { // A == B == C
                    S = B;
                    return true;
                }
                S = C;
                return true;
            } else {                                  // A != B
                if (diff_bc.getEditDistance() == 0) { // A != B == C
                    S = A;                              
                    return true;
                } else {                              // A != B != C
                    S = merge_();
                    if (isConflict()) {               // conflict occured
                        return false;
                    }
                }
            }
            return true;
        }
        
        /**
         * compose differences
         */
        void compose () {
            diff_ba.compose();
            diff_bc.compose();
        }
        
    private :
        /**
         * merge implementation
         */
        sequence merge_ () {
            elemVec         seq;
            Ses< elem >     ses_ba   = diff_ba.getSes();
            Ses< elem >     ses_bc   = diff_bc.getSes();
            sesElemVec      ses_ba_v = ses_ba.getSequence();
            sesElemVec      ses_bc_v = ses_bc.getSequence();
            sesElemVec_iter ba_it    = ses_ba_v.begin();
            sesElemVec_iter bc_it    = ses_bc_v.begin();
            sesElemVec_iter ba_end   = ses_ba_v.end();
            sesElemVec_iter bc_end   = ses_bc_v.end();
            
            while (!isEnd(ba_end, ba_it) || !isEnd(bc_end, bc_it)) {
                while (true) {
                    if (!isEnd(ba_end, ba_it)            && 
                        !isEnd(bc_end, bc_it)            &&
                        ba_it->first == bc_it->first     && 
                        ba_it->second.type == SES_COMMON && 
                        bc_it->second.type == SES_COMMON) {
                        // do nothing
                    } else {
                        break;
                    }
                    if      (!isEnd(ba_end, ba_it)) seq.push_back(ba_it->first);
                    else if (!isEnd(bc_end, bc_it)) seq.push_back(bc_it->first);
                    forwardUntilEnd(ba_end, ba_it);
                    forwardUntilEnd(bc_end, bc_it);
                }
                if (isEnd(ba_end, ba_it) || isEnd(bc_end, bc_it)) break;
                if (   ba_it->second.type == SES_COMMON 
                       && bc_it->second.type == SES_DELETE) {
                    forwardUntilEnd(ba_end, ba_it);
                    forwardUntilEnd(bc_end, bc_it);
                } else if (ba_it->second.type == SES_COMMON && 
                           bc_it->second.type == SES_ADD) {
                    seq.push_back(bc_it->first);
                    forwardUntilEnd(bc_end, bc_it);
                } else if (ba_it->second.type == SES_DELETE && 
                           bc_it->second.type == SES_COMMON) {
                    forwardUntilEnd(ba_end, ba_it);
                    forwardUntilEnd(bc_end, bc_it);
                } else if (ba_it->second.type == SES_DELETE && 
                           bc_it->second.type == SES_DELETE) {
                    if (ba_it->first == bc_it->first) {
                        forwardUntilEnd(ba_end, ba_it);
                        forwardUntilEnd(bc_end, bc_it);
                    } else {
                        // conflict
                        conflict = true;
                        return B;
                    }
                } else if (ba_it->second.type == SES_DELETE && 
                           bc_it->second.type == SES_ADD) {
                    // conflict
                    conflict = true;
                    return B;
                } else if (ba_it->second.type == SES_ADD && 
                           bc_it->second.type == SES_COMMON) {
                    seq.push_back(ba_it->first);
                    forwardUntilEnd(ba_end, ba_it);
                } else if (ba_it->second.type == SES_ADD && 
                           bc_it->second.type == SES_DELETE) {
                    // conflict
                    conflict = true;
                    return B;
                } else if (ba_it->second.type == SES_ADD && 
                           bc_it->second.type == SES_ADD) {
                    if (ba_it->first == bc_it->first) {
                        seq.push_back(ba_it->first);
                        forwardUntilEnd(ba_end, ba_it);
                        forwardUntilEnd(bc_end, bc_it);
                    } else {
                        // conflict
                        conflict = true;
                        return B;
                    }
                }
            }
            
            if (isEnd(ba_end, ba_it)) {
                addDecentSequence(bc_end, bc_it, seq);
            } else if (isEnd(bc_end, bc_it)) {
                addDecentSequence(ba_end, ba_it, seq);
            }
            
            sequence mergedSeq(seq.begin(), seq.end());
            return mergedSeq;
        }
        
        /**
         * join elem vectors
         */
        void inline joinElemVec (elemVec& s1, elemVec& s2) const {
            if (!s2.empty()) {
                for (elemVec_iter vit=s2.begin();vit!=s2.end();++vit) {
                    s1.push_back(*vit);
                }
            }
        }
        
        /**
         * check if sequence is at end
         */
        template <typename T_iter>
        bool inline isEnd (const T_iter& end, const T_iter& it) const {
            return it == end ? true : false;
        }
        
        /**
         * increment iterator until iterator is at end
         */
        template <typename T_iter>
        void inline forwardUntilEnd (const T_iter& end, T_iter& it) const {
            if (!isEnd(end, it)) ++it;
        }
        
        /**
         * add elements whose SES's type is ADD
         */
        void inline addDecentSequence (const sesElemVec_iter& end, sesElemVec_iter& it, elemVec& seq) const {
            while (!isEnd(end, it)) {
                if (it->second.type == SES_ADD) seq.push_back(it->first);
                ++it;
            }      
        }
        
    };
}

#endif // DTL_DIFF3_H
