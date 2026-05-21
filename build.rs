fn main() {
    cc::Build::new()
        .file("csrc/rand.c")
        .include("csrc")
        .opt_level(3)
        .warnings(false)
        .compile("isaac");

    cc::Build::new()
        .file("csrc/xtea.c")
        .include("csrc")
        .opt_level(3)
        .warnings(false)
        .compile("xtea");

    cc::Build::new()
        .file("csrc/whirlpool.c")
        .include("csrc")
        .opt_level(3)
        .warnings(false)
        .compile("whirlpool");
}
