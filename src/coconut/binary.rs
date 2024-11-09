
use std::fs;
use iced_x86;
use std::collections::HashMap;
use std::collections::hash_map::Values;

use object::{Architecture, File, ObjectSection, ReadRef};
use object::{Object};
use object::pe::ImageNtHeaders32;
use object::pe::ImageNtHeaders64;
use object::read::pe::{PeFile};

use ouroboros::self_referencing;

use super::function::Function;


enum AnyFile<'data> {
    Pe32(PeFile<'data, ImageNtHeaders32>),
    Pe64(PeFile<'data, ImageNtHeaders64>),
    Unknown(File<'data>),
}

trait AnyFileTrait<'data> {
    fn base_address(&self) -> u64;
    fn architecture(&self) -> Architecture;
    fn entry_point(&self) -> u64;
}

impl<'data> AnyFileTrait<'data> for AnyFile<'data> {
    fn base_address(&self) -> u64 {
        match self {
            AnyFile::Pe32(file) => file.relative_address_base(),
            AnyFile::Pe64(file) => file.relative_address_base(),
            AnyFile::Unknown(file) => file.relative_address_base(),
        }

    }
    
    
    fn architecture(&self) -> Architecture {
        match self {
            AnyFile::Pe32(file) => file.architecture(),
            AnyFile::Pe64(file) => file.architecture(),
            AnyFile::Unknown(file) => file.architecture(),
        }

    }

    fn entry_point(&self) -> u64 {
        match self {
            AnyFile::Pe32(pe) => pe.entry(),
            AnyFile::Pe64(pe) => pe.entry(),
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
            Err(e) => eprintln!("Failed to read file: {}", e),
        }

        self.get_imports();
    }

    pub fn get_path(&self) -> String {
        self.with_path(|path| path.clone())
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


    pub fn build_disassembly(&mut self) {
        let mut functions: Vec<Function> = Vec::new();

        self.with_object(|object| {
            let object = object.as_ref().unwrap();
            
            if let AnyFile::Pe32(pe) = &object {
                let text_section = pe.section_by_name(".text");

                if text_section.is_none() {
                    eprintln!("text section not found in binary");
                    return;
                }

                let text_section = text_section.unwrap();


                let mut decoder = iced_x86::Decoder::new(
                    32,
                    text_section.data().unwrap(),
                    iced_x86::DecoderOptions::NONE,
                );

                decoder.set_ip(object.entry_point());

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

                        functions.push(function);

                        current_address = instruction.next_ip() as usize;

                        instructions.clear();

                        continue;
                    }

                    instructions.push(instruction);

                }
            }
            
        });

        self.with_functions_mut(|self_functions| {
            for function in functions {
                self_functions.insert(function.address, function);
            }
        })
    }

    fn build_object_file(data: &[u8]) -> AnyFile {
        let file_kind = object::FileKind::parse(data).unwrap();

        match file_kind {
            object::FileKind::Pe32 => {
                let pe_file = PeFile::parse(data).unwrap();
                AnyFile::Pe32(pe_file)
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
