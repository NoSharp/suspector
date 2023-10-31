#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pe.h"

#define BIT_MASK_63 (1 << 63) - 1

u8 rva_to_offset(u64 rva, IMAGE_SECTION_HEADER* sections, size_t header_sz, u64* out){
  for(u32 i = 0; i < header_sz; i++){
    IMAGE_SECTION_HEADER section = sections[i];
    if(rva >= section.VirtualAddress && rva <= section.VirtualAddress + section.Misc.VirtualSize){
      u32 section_offset = rva - section.VirtualAddress;
      *out = section.PointerToRawData + section_offset;
      return 1;
    }
  }
  return 0;
}


u8 read_string_rva(u64 rva, IMAGE_SECTION_HEADER* sections, size_t header_sz, char* out, FILE* file){
  u64 file_offset = 0;
  u8 is_success = rva_to_offset(rva, sections, header_sz, &file_offset);
  if(is_success == 0){
    printf("Invalid RVA: %x\n", rva);
    return 0;
  }
  fseek(file, file_offset, SEEK_SET);
  fgets(out, 128, file);
  return 1;
}

u8 is_suspect(const char* file_name){
  FILE* file = fopen(file_name, "rb");
  
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
  fread(dos_header, sizeof(IMAGE_DOS_HEADER), 1, file);
  // little endian.
  if(dos_header->e_magic != 0x5A4D){
    printf("Unsupported file format, Magic mismatch");
    return 0;
  }

  // offset to PE header.
  fseek(file, 0x3C, SEEK_SET);

  __int32 pe_offset = 0;
  fread(&pe_offset, 4, 1, file);
  fseek(file, pe_offset, SEEK_SET);
  
  IMAGE_NT_HEADERS64* image_header = (IMAGE_NT_HEADERS64*)malloc(sizeof(IMAGE_NT_HEADERS64));
  fread(image_header, sizeof(IMAGE_NT_HEADERS64), 1, file);
  if(image_header->Signature != 0x4550){
    printf("Unsupported file format, PE magic");
    return 0;
  }

  IMAGE_DATA_DIRECTORY import = image_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  
  u32 sections_amt = image_header->FileHeader.NumberOfSections;
  IMAGE_SECTION_HEADER* sections = malloc(sizeof(IMAGE_SECTION_HEADER) * sections_amt);
  fread(sections, sizeof(IMAGE_SECTION_HEADER), sections_amt, file);

  u64 import_addr = 0;
  u8 is_success = rva_to_offset(import.VirtualAddress, sections, sections_amt, &import_addr);
  if(is_success == 0){
    return 0;
  }
  
  fseek(file, import_addr, SEEK_SET);
  u32 import_amt = (import.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));
  IMAGE_IMPORT_DESCRIPTOR* imports = malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * import_amt);
  fread(imports, sizeof(IMAGE_IMPORT_DESCRIPTOR), import_amt, file);

  for(u32 i = 0; i < import_amt; i++){
    IMAGE_IMPORT_DESCRIPTOR import_info = imports[i];
    
    if(import_info.Name == 0){
      continue;
    }

    char* module_name = (char*)malloc(sizeof(char) * 128);
    is_success = read_string_rva(import_info.Name, sections, sections_amt, module_name, file);
    if(is_success == 0){
      printf("Bailing invalid offset 1 @ %d RVA: %x\n" , i, import_info.Name);
      continue;
    }

    u64 iat_offset = 0;
    if(import_info.OriginalFirstThunk == 0){
      printf("No first thunk 1\n");
      continue;
    }

    is_success = rva_to_offset(import_info.OriginalFirstThunk , sections, sections_amt, &iat_offset);
    if(is_success == 0){
      printf("Cannot locate IAT for %s RVA %d\n", module_name, import_info.OriginalFirstThunk);
      return 0;
    }

    u64 flags = 0;
    u16 hint = 0;
    char* name_buffer = (char*)malloc(sizeof(char) * 128);
    fseek(file, iat_offset, SEEK_SET);
    for(u32 i = 0; i < 10000; i++){
      fread(&flags, sizeof(u64), 1, file);
      if(flags & 0b1 == 1){
        // ordinal
        // dont read anymore
      }else{
        u64 old_pos = 0;
        fgetpos(file, &old_pos);

        if(!rva_to_offset(flags & (BIT_MASK_63), sections, sections_amt, &iat_offset)){
          printf("Bailing invalid offset %x %x\n", flags & (BIT_MASK_63), flags);
          goto out;
        }
        fseek(file, iat_offset, SEEK_SET);
        fread(&hint, sizeof(u16), 1, file);
        fgets(name_buffer, 128, file);
        fseek(file, old_pos, SEEK_SET);
        printf("name: %s\n", name_buffer);

        if(name_buffer[0] == 0 && hint == 0 && flags == 0){
          goto out;
        }  
      }
      
    }
    out:
    
  }
  return 1;
}

int main(int argc, char *argv[]){
  if(argc == 0){
    printf("specify a file path");
    return 0;
  }
  
  printf("opening: %s\n", argv[1]);
  is_suspect(argv[1]);
}