cmake_minimum_required (VERSION 2.8)
project (proc_doppel)

set (srcs
	main.cpp
	util.cpp
	ntdll_undoc.cpp
	pe_hdrs_helper.cpp
)

set (hdrs
	util.h
	ntdll_undoc.h
	ntdll_types.h
	ntddk.h
	pe_hdrs_helper.h
)

add_executable (proc_doppel ${hdrs} ${srcs})