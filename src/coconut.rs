
pub mod binary;
mod function;

use rfd;
use eframe::egui;
use iced_x86::Formatter;
use object::ObjectSection;
use binary::Binary;
use binary::build_new_binary;

#[derive(PartialEq)]
enum CurrentView {
    File,
    Disassembly,
    Hex
}


pub struct Coconut {
    pub(crate) binary: Option<Binary>,
    
    current_view: CurrentView,
    current_address: usize,
    current_address_is_func: bool,
    current_address_viewed: bool,
    function_filter: String,



}

impl Coconut {
    pub fn new() -> Self {
        Coconut {
            binary: None,
            current_view: CurrentView::File,
            current_address: 0,
            current_address_is_func: false,
            current_address_viewed: true,
            function_filter: "".to_string(),
        }
    }

    fn setup_spacing(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(8.0, 4.0);
        ctx.set_style(style);
    }

    fn add_file_info(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("file_grid")
            .striped(true)
            .show(ui, |ui| {
                if self.binary.is_some() {
                    let binary = self.binary.as_mut().unwrap();

                    ui.label("Filename");
                    ui.label(binary.get_path());
                    ui.end_row();

                    ui.label("Size");

                    ui.label(format!("0x{:x} bytes", binary.get_file_size()));
                }
            });
    }

    fn add_section_info(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Sections")
            .default_open(true)
            .show(ui, |ui| {
                egui::Grid::new("sections_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Name");
                        ui.label("Address");
                        ui.label("Size");
                        ui.end_row();

                        if self.binary.is_some() {
                            //let binary = self.binary.as_mut().unwrap();

                            /*
                            if binary.get_sections().is_some() {
                                for section in binary.get_sections().unwrap() {
                                    ui.label(section.name().unwrap_or("<unknown>"));
                                    ui.label(format!(
                                        "{:08x}", section.address()
                                    ));
                                    ui.label(format!(
                                        "{:04x}", section.size()
                                    ));


                                    ui.end_row()
                                }
                            }
                            */
                        }
                    });
            });
    }

    fn add_function_list(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Functions")
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.function_filter)
                            .hint_text("Filter")
                            .desired_width(150.0),
                    );

                    if ui.add(egui::Button::new("❌").small()).clicked() {
                        self.function_filter.clear();
                    }
                });

                egui::ScrollArea::vertical()
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        egui::Grid::new("functions_grid")
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label("Address");
                                ui.label("Name");
                                ui.end_row();

                                if self.binary.is_some() {
                                    let binary = self.binary.as_mut().unwrap();

                                    let functions = binary.get_functions();

                                    if !functions.is_some() {
                                        eprintln!("Functions are not available");
                                    }

                                    for function in functions.unwrap() {
                                        if self.function_filter.is_empty() || function.get_name().contains(self.function_filter.as_str()) {
                                            let address_button = ui.button(format!("{:08x}", function.get_address()));
                                            
                                            if address_button.clicked() {
                                                self.current_view = CurrentView::Disassembly;
                                                self.current_address = function.get_address();
                                                self.current_address_is_func = true;
                                                self.current_address_viewed = false;
                                            }
                                            
                                            ui.label(function.get_name());
                                            ui.end_row();
                                        }
                                    }
                                }
                            });
                    });
            });
    }

    fn add_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open").clicked() {
                        if let Some(file) = rfd::FileDialog::new().pick_file() {
                            let mut binary = build_new_binary();
                            binary.open_file(file.to_str().unwrap());
                            binary.build_disassembly();

                            self.binary = Some(binary);
                            self.current_view = CurrentView::File;
                            self.current_address_is_func = false;
                            self.current_address_viewed = false;
                            self.current_address = 0;
                        }
                        ui.close_menu()
                    }

                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });

                ui.menu_button("View", |ui| {
                    if ui.selectable_value(&mut self.current_view, CurrentView::File, "File").clicked() {
                        ui.close_menu();
                    }
                    if ui.selectable_value(&mut self.current_view, CurrentView::Disassembly, "Disassembly").clicked() {
                        ui.close_menu();
                    }
                    if ui.selectable_value(&mut self.current_view, CurrentView::Hex, "Hex").clicked() {
                        ui.close_menu();
                    }
                });
            });
        });
    }

    fn add_bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            let viewed_indicator = if !self.current_address_viewed {"*"} else {""};

            ui.label(format!("Address: 0x{:08x}{}", self.current_address, viewed_indicator));
        });
    }

    fn add_left_side_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("left_side_panel")
            .resizable(false)
            .exact_width(250.0)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    self.add_section_info(ui);

                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            self.add_function_list(ui);
                        });
                });
            });
    }

    fn add_right_side_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::right("right_side_panel")
            .resizable(false)
            .show(ctx, |_ui| {});
    }

    fn add_central_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .show(ctx, |ui| {
                match self.current_view {
                    CurrentView::File => {
                        self.add_file_info(ui);

                    }
                    CurrentView::Disassembly => {
                        self.display_disassembly(ui);
                    }
                    CurrentView::Hex => {
                        self.display_hexdump(ui);
                    }
                }
            });
    }

    fn display_disassembly(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("disassembly_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        if self.binary.is_some() && self.current_address_is_func {
                            let binary = self.binary.as_mut().unwrap();

                            let function = binary.get_function_at_address(self.current_address);
                            if function.is_none() {
                                eprintln!("Function {:08x} not found", self.current_address);
                            }

                            let mut formatter = iced_x86::NasmFormatter::new();


                            let mut mnemonic = String::new();
                            let mut operands = String::new();
                            for instruction in function.unwrap().get_instructions() {
                                ui.label(format!("{:08x}", instruction.ip()));

                                formatter.format_mnemonic(&instruction, &mut mnemonic);
                                formatter.format_all_operands(&instruction, &mut operands);

                                ui.label(mnemonic.as_str());

                                if instruction.mnemonic() == iced_x86::Mnemonic::Call {
                                    if instruction.near_branch_target() != 0 && binary.get_function_at_address(instruction.near_branch_target() as usize).is_some() {
                                        if ui.button(format!("{}", operands.as_str())).clicked() {
                                            self.current_address = instruction.near_branch_target() as usize;
                                            self.current_address_is_func = true;
                                            self.current_address_viewed = false;
                                        }
                                    } else {
                                        ui.label(operands.as_str());
                                    }
                                } else {
                                    ui.label(operands.as_str());
                                }

                                ui.end_row();

                                mnemonic.clear();
                                operands.clear();
                            }
                        }
                    });
            });
    }

    fn display_hexdump(&mut self, ui: &mut egui::Ui) {
        let bytes_per_line = 16;

        if let Some(binary) = &self.binary {
            let data = binary.get_data(); // Assume data is a byte slice
            let base_address = binary.get_base_address() as usize; // Assume base_address is usize
            let total_lines = (data.len() + bytes_per_line - 1) / bytes_per_line;

            let mut target_line = 0;
            if self.current_address >= base_address {
                target_line = (self.current_address - base_address) / bytes_per_line;
            }
            

            egui::ScrollArea::vertical()
                .auto_shrink([false, true])
                .show_rows(ui, ui.text_style_height(&egui::TextStyle::Body), total_lines, |ui, row_range| {
                    
                    egui::Grid::new("hexdump_grid")
                        .striped(true)
                        .show(ui, |ui| {
                            // Display only the lines within the current viewport range
                            for i in row_range {
                                // Calculate address for the current line
                                let address = base_address + i * bytes_per_line;

                                // Display the address
                                ui.label(format!("{:08X}", address));

                                // Concatenate hex bytes for the line
                                let hex_bytes: String = (0..bytes_per_line)
                                    .map(|j| {
                                        if let Some(&byte) = data.get(i * bytes_per_line + j) {
                                            format!("{:02X} ", byte)
                                        } else {
                                            "   ".to_string() // Empty space for missing data
                                        }
                                    })
                                    .collect();

                                // Display the concatenated hex bytes
                                ui.monospace(hex_bytes.trim_end());

                                // Concatenate ASCII characters for the line
                                let ascii_repr: String = (0..bytes_per_line)
                                    .map(|j| {
                                        if let Some(&byte) = data.get(i * bytes_per_line + j) {
                                            if byte.is_ascii_graphic() || byte == b' ' {
                                                byte as char
                                            } else {
                                                '.'
                                            }
                                        } else {
                                            ' ' // Empty space for missing data
                                        }
                                    })
                                    .collect();

                                // Display the ASCII representation
                                ui.monospace(ascii_repr);

                                // End the row for this line
                                ui.end_row();
                            }
                        });

                    if !self.current_address_viewed {
                        let target_offset = target_line as f32 * ui.text_style_height(&egui::TextStyle::Body);
                        let current_offset = ui.min_rect().top();
                        let scroll_delta = target_offset - current_offset;

                        ui.scroll_with_delta(egui::emath::Vec2::new(0.0, 0.0 - scroll_delta));
                        self.current_address_viewed = true;
                    }
                    
                });
            
        }

    }
}

impl eframe::App for Coconut {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Coconut::setup_spacing(ctx);

        self.add_top_panel(ctx);
        self.add_bottom_panel(ctx);
        self.add_left_side_panel(ctx);
        self.add_right_side_panel(ctx);
        self.add_central_panel(ctx);
    }
}