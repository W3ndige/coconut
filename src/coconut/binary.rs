use std::fs;
use iced_x86;

use std::collections::{
    HashMap,
    hash_map::Values,
};

use object::{Architecture, File, Object, ObjectSection, endian::{
    LittleEndian,
    BigEndian,
}, pe::{
    ImageNtHeaders32,
    ImageNtHeaders64,
}, macho::{
    MachHeader32,
    MachHeader64,
    CPU_TYPE_X86,
    CPU_TYPE_X86_64,
    CPU_TYPE_ARM,
    CPU_TYPE_ARM64
    
}, read::{
    macho::MachOFile,
    pe::PeFile,
}, FileKind};


use ouroboros::self_referencing;

use super::function::Function;


enum AnyFile<'data> {
    Pe32(PeFile<'data, ImageNtHeaders32>),
    Pe64(PeFile<'data, ImageNtHeaders64>),
    MachO32(MachOFile<'data, MachHeader32<LittleEndian>>),
    MachO64(MachOFile<'data, MachHeader64<LittleEndian>>),
    Unknown(File<'data>),
}

trait AnyFileTrait<'data> {
    fn base_address(&self) -> u64;
    fn architecture(&self) -> Architecture;
    fn kind(&self) -> Option<FileKind>;
    fn entry_point(&self) -> u64;
}

impl<'data> AnyFileTrait<'data> for AnyFile<'data> {
    fn base_address(&self) -> u64 {
        match self {
            AnyFile::Pe32(file) => file.relative_address_base(),
            AnyFile::Pe64(file) => file.relative_address_base(),
            AnyFile::MachO32(file) => file.relative_address_base(),
            AnyFile::MachO64(file) => file.relative_address_base(),
            AnyFile::Unknown(file) => file.relative_address_base(),
        }
    }
    
    
    fn architecture(&self) -> Architecture {
        match self {
            AnyFile::Pe32(file) => file.architecture(),
            AnyFile::Pe64(file) => file.architecture(),
            AnyFile::MachO32(file) => file.architecture(),
            AnyFile::MachO64(file) => file.architecture(),
            AnyFile::Unknown(file) => file.architecture(),
        }
    }
    
    fn kind(&self) -> Option<FileKind> {
        match self {
            AnyFile::Pe32(_) => Some(FileKind::Pe32),
            AnyFile::Pe64(_) => Some(FileKind::Pe64),
            AnyFile::MachO32(_) => Some(FileKind::MachO32),
            AnyFile::MachO64(_) => Some(FileKind::MachO64),
            AnyFile::Unknown(_) => None,
        }
    }

    fn entry_point(&self) -> u64 {
        match self {
            AnyFile::Pe32(pe) => pe.entry(),
            AnyFile::Pe64(pe) => pe.entry(),
            AnyFile::MachO32(macho) => macho.entry(),
            AnyFile::MachO64(macho) => macho.entry(),
            AnyFile::Unknown(file) => file.entry(),
        }
    }
}

#[self_referencing]
pub struct Binary {
    path: String,
    data: Vec<u8>,
    #[borrows(data)]
    #[covariant]
    object: Option<AnyFile<'this>>,

    functions: HashMap<usize, Function>,
}

impl Binary {
    pub fn open_file(&mut self, path: &str) {
        let path_string = path.to_string();

        match fs::read(path) {
            Ok(data) => {
                // Rebuild the self-referential struct with the new data
                let new_binary = BinaryBuilder {
                    path: path_string,
                    data: data,
                    object_builder: |data| {
                        Some(
                            Binary::build_object_file(data)
                        )
                    },
                    functions: HashMap::new(),
                }.build();

                // Replace the current struct with the new one
                *self = new_binary;

            },
            Err(e) => panic!("Failed to read file: {}", e),
        }
    }

    pub fn get_path(&self) -> String {
        self.with_path(|path| path.clone())
    }
    
    pub fn get_kind(&self) -> Option<FileKind> {
        self.with_object(|object| {
            let object = object.as_ref().unwrap();

            object.kind()
        })
    }

    pub fn get_file_size(&self) -> usize {
        self.with_data(|data| data.len())
    }
    
    pub fn get_base_address(&self) -> u64 {
        self.with_object(|object| {
            let object = object.as_ref().unwrap();

            object.base_address()
        })
    }

    pub fn get_architecture(&self) -> Architecture {
        self.with_object(|object| {
            let object = object.as_ref().unwrap();

            object.architecture()
        })
    }
    
    pub fn get_data(&self) -> &Vec<u8> {
        self.with_data(|data| {
            data
        })
    }
    

    pub fn get_functions(&self) -> Option<Values<'_, usize, Function>> {
        self.with_functions(|functions| {
            return Some(functions.values());
        })
    }
    
    pub fn get_function_at_address(&self, address: usize) -> Option<&Function> {
        self.with_functions(|functions| {
            return functions.get(&address);
        })
    }

    pub fn get_imports(&self) {
        self.with_object(|object| {
            let object = object.as_ref().unwrap();

            if let AnyFile::Pe32(pe) = &object {
                let import_table = pe.import_table().unwrap().unwrap();
                let descriptors = import_table.descriptors().unwrap();

                for descriptor in descriptors {
                    let descriptor = descriptor.unwrap();
                    
                    let descriptor_name_addr = descriptor.name.get(object::LittleEndian) + 1;
                    
                    println!("Imports: {:x}", descriptor_name_addr);
                    
                    self.with_data(move |data| {
                        let descriptor_name = data.get(descriptor_name_addr as usize).unwrap();
                        
                        println!("{:x?}", descriptor_name);
                        
                    })

                }
            }
        })
    }

    fn disassemble_with_iced(entry: u64, bitness: u32, data: &[u8]) -> HashMap<usize, Function>{
        let mut functions: HashMap<usize, Function> = HashMap::new();

        let mut decoder = iced_x86::Decoder::new(
            bitness,
            data,
            iced_x86::DecoderOptions::NONE,
        );

        decoder.set_ip(entry);

        let mut function_name = "entry".to_string();
        let mut current_address: usize = 0;
        let mut instructions: Vec<iced_x86::Instruction> = Vec::new();
        let mut instruction: iced_x86::Instruction = iced_x86::Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if current_address == 0 {
                current_address = instruction.ip() as usize;
            }

            if instruction.mnemonic() == iced_x86::Mnemonic::Ret {
                instructions.push(instruction);

                let function = Function::new(function_name.clone(), current_address, instructions.clone());

                function_name.clear();
                function_name = format!("sub_{:08x}", instruction.next_ip());

                functions.insert(function.address, function);

                current_address = instruction.next_ip() as usize;

                instructions.clear();

                continue;
            }

            instructions.push(instruction);

        }

        functions

    }


    pub fn build_disassembly(&mut self) {
        let mut funcs: HashMap<usize, Function> = HashMap::new();

        self.with_object(|object| {
            let object = object.as_ref().unwrap();

            if let AnyFile::Pe32(pe) = &object {
                let text_section = pe.section_by_name(".text");

                if text_section.is_none() {
                    eprintln!("text section not found in binary");
                    return;
                }

                let text_section = text_section.unwrap();

                funcs = Binary::disassemble_with_iced(pe.entry(), 32, text_section.data().unwrap());
            } else if let AnyFile::Pe64(pe) = &object {
                let text_section = pe.section_by_name(".text");

                if text_section.is_none() {
                    eprintln!("text section not found in binary");
                    return;
                }

                let text_section = text_section.unwrap();

                funcs = Binary::disassemble_with_iced(pe.entry(), 64, text_section.data().unwrap());
            } else if let AnyFile::MachO32(macho) = &object {
                let text_section = macho.section_by_name("__text");

                if text_section.is_none() {
                    eprintln!("text section not found in binary");
                    return;
                }

                let text_section = text_section.unwrap();

                let cpu_type = macho.macho_header().cputype.get(LittleEndian);

                match cpu_type {
                    CPU_TYPE_X86 => funcs = Binary::disassemble_with_iced(macho.entry(), 64, text_section.data().unwrap()),
                    CPU_TYPE_ARM => panic!("Unimplemented ARM64 disassembly"),
                    _ => panic!("Unknown architecture"),
                };

            } else if let AnyFile::MachO64(macho) = &object {
                let text_section = macho.section_by_name("__text");

                if text_section.is_none() {
                    eprintln!("text section not found in binary");
                    return;
                }

                let text_section = text_section.unwrap();

                let cpu_type = macho.macho_header().cputype.get(LittleEndian);

                match cpu_type {
                    CPU_TYPE_X86_64 => funcs = Binary::disassemble_with_iced(macho.entry(), 64, text_section.data().unwrap()),
                    CPU_TYPE_ARM64 => panic!("Unimplemented ARM64 disassembly"),
                    _ => panic!("Unknown architecture"),
                };

            }
        });

        self.with_functions_mut(|mut functions| {
            functions.extend(funcs);
        })
    }

    fn build_object_file(data: &[u8]) -> AnyFile {
        let file_kind = object::FileKind::parse(data).unwrap();

        match file_kind {
            object::FileKind::Pe32 => {
                let pe_file = PeFile::parse(data).unwrap();
                AnyFile::Pe32(pe_file)
            }
            
            object::FileKind::Pe64 => {
                let pe_file = PeFile::parse(data).unwrap();
                AnyFile::Pe64(pe_file)
            }

            object::FileKind::MachO32 => {
                let macho_file = MachOFile::parse(data).unwrap();
                AnyFile::MachO32(macho_file)
            }

            object::FileKind::MachO64 => {
                let macho_file = MachOFile::parse(data).unwrap();
                AnyFile::MachO64(macho_file)
            }
            
            _ => {
                let file = object::File::parse(data).unwrap();
                AnyFile::Unknown(file)
            }
        }
    }
}


pub fn build_new_binary() -> Binary {
    BinaryBuilder {
        path: String::new(),
        data: vec![],
        object_builder: |_| None,
        functions: HashMap::new(),
    }.build()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_get_path() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);
        
        let new_path = binary.get_path();

        assert_eq!(path.to_string(), new_path)
    }

    #[test]
    fn test_binary_get_kind_pe32() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);

        let kind = binary.get_kind().unwrap();

        assert_eq!(kind, FileKind::Pe32)
    }

    #[test]
    fn test_binary_get_kind_pe64() {
        let path = "./testdata/pe64_44fc749f1e8069f218d721eb1adbc5958fd6cdb7a535f899cf6726d19dd40d7b";

        let mut binary = build_new_binary();
        binary.open_file(path);

        let kind = binary.get_kind().unwrap();

        assert_eq!(kind, FileKind::Pe64)
    }

    #[test]
    fn test_binary_get_base_address() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);

        let base_address = binary.get_base_address();

        assert!(base_address != 0);
    }

    #[test]
    fn test_binary_get_file_size() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);

        let file_size = binary.get_file_size();

        assert!(file_size > 0);
    }
    
    #[test]
    fn test_binary_get_architecture() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);

        let architecture = binary.get_architecture();

        assert_eq!(architecture, Architecture::I386);
    }
    
    #[test]
    fn test_binary_read_data() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);

        assert!(binary.get_data().len() > 0);
    }
    
    #[test]
    fn test_binary_build_disassembly() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);
        binary.build_disassembly();
        
        let functions = binary.get_functions();

        assert!(functions.is_some());
        
        let functions = functions.unwrap();
        
        assert!(functions.len() > 0);
    }
    
    #[test]
    fn test_binary_get_function_instructions() {
        let path = "./testdata/pe32_c2e624bf51248e2a8ab114c562c0eaf5d40d841382fd188f6d693a51def1465f";

        let mut binary = build_new_binary();
        binary.open_file(path);
        binary.build_disassembly();

        let functions = binary.get_functions();

        assert!(functions.is_some());

        let functions = functions.unwrap();

        for function in functions {
            assert!(function.get_instructions().len() > 0);
        }
    }
}
