#pragma once

#include <Windows.h>

BYTE *buffer_payload(wchar_t *filename, OUT size_t &r_size);
void free_buffer(BYTE* buffer, size_t buffer_size);
