/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_GCMA_H__
#define __MM_GCMA_H__

#ifdef CONFIG_GCMA
void gcma_area_init(unsigned long pfn, unsigned long page_count);
void gcma_discard_range(unsigned long start_pfn, unsigned long end_pfn);
void gcma_free_range(unsigned long start_pfn, unsigned long end_pfn);
#else
void gcma_area_init(unsigned long pfn, unsigned long page_count) {};
void gcma_discard_range(unsigned long start_pfn, unsigned long end_pfn) {};
void gcma_free_range(unsigned long start_pfn, unsigned long end_pfn) {};
#endif
#endif
