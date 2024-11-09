use iced_x86;

#[derive(Debug)]
pub struct Function {
    pub name: String,
    pub address: usize,
    pub instructions: Vec<iced_x86::Instruction>,
}

impl Function {
    pub fn new(mut name: String, address: usize, instructions: Vec<iced_x86::Instruction>) -> Self {
        if name.is_empty() {
            name = format!("0x{:08x}", address);
        }

        Function { name, address, instructions}
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_address(&self) -> usize {
        self.address
    }

    pub fn get_instructions(&self) -> &Vec<iced_x86::Instruction> {
        &self.instructions
    }
}