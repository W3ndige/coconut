mod coconut;

use coconut::Coconut;


fn main() {
    let options = eframe::NativeOptions::default();
    
    eframe::run_native(
        "Coconut",
        options,
        Box::new(|_cc| Ok(Box::new(Coconut::new()))),
    ).expect("Couldn't create eframe::egui application");

}

