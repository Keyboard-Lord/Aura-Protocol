use aura_reference_demo_v1::{render_reference_demo_report_v1, run_reference_demo_v1};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let artifacts = run_reference_demo_v1()?;
    print!("{}", render_reference_demo_report_v1(&artifacts));
    Ok(())
}
