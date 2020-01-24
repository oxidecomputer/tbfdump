use std::fs::File;
use std::io::Read;

use pretty_hex::*;
use riscv_disasm::*;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderV2Base {
    version: u16,
    header_size: u16,
    total_size: u32,
    flags: u32,
    checksum: u32,
}

/// Types in TLV structures for each optional block of the header.
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum TbfHeaderTypes {
    TbfHeaderMain = 1,
    TbfHeaderWriteableFlashRegions = 2,
    TbfHeaderPackageName = 3,
    Unused = 5,
}

/// The TLV header (T and L).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderTlv {
    tipe: TbfHeaderTypes,
    length: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct TbfHeaderV2Main {
    init_fn_offset: u32,
    protected_size: u32,
    minimum_ram_size: u32,
}

#[repr(C)]
struct LayoutHeader32 {
    got_sym_start: u32,
    got_start: u32,
    got_size: u32,
    data_sym_start: u32,
    data_start: u32,
    data_size: u32,
    bss_start: u32,
    bss_size: u32,
    reldata_start: u32,
    stack_size: u32,
}

fn read_tbf_header(reader: &mut dyn Read) -> Option<TbfHeaderV2Base> {
    let mut h = [0u8; std::mem::size_of::<TbfHeaderV2Base>()];
    match reader.read_exact(&mut h[..]) {
        Ok(_) => Some(unsafe { std::mem::transmute(h) }),
        _ => None,
    }
}

fn read_tbf_tlv(reader: &mut dyn Read) -> Option<TbfHeaderTlv> {
    let mut h = [0u8; std::mem::size_of::<TbfHeaderTlv>()];
    match reader.read_exact(&mut h[..]) {
        Ok(_) => Some(unsafe { std::mem::transmute(h) }),
        _ => None,
    }
}

fn read_tbf_main(reader: &mut dyn Read) -> Option<TbfHeaderV2Main> {
    let mut h = [0u8; std::mem::size_of::<TbfHeaderV2Main>()];
    match reader.read_exact(&mut h[..]) {
        Ok(_) => Some(unsafe { std::mem::transmute(h) }),
        _ => None,
    }
}

fn read_layout_header32(reader: &mut dyn Read) -> Option<LayoutHeader32> {
    let mut h = [0u8; std::mem::size_of::<LayoutHeader32>()];
    match reader.read_exact(&mut h[..]) {
        Ok(_) => Some(unsafe { std::mem::transmute(h) }),
        _ => None,
    }
}

fn main() {
    let mut file = File::open("rv32imac.tbf").expect("foo");

    let header = read_tbf_header(&mut file).expect("ok");

    println!("version          {:x?}", header.version);
    println!("header_size      {:x?}", header.header_size);
    println!("total_size       {:x?}", header.total_size);
    println!("flags            {:x?}", header.flags);
    println!("checksum         {:x?}", header.checksum);
    println!("");

    hh(
        &mut file,
        header.header_size as u64 - std::mem::size_of::<TbfHeaderV2Base>() as u64,
    );

    let layout = read_layout_header32(&mut file).expect("ok");
    println!("got_sym_start  {:x}", layout.got_sym_start);
    println!("got_start      {:x}", layout.got_start);
    println!("got_size       {:x}", layout.got_size);
    println!("data_sym_start {:x}", layout.data_sym_start);
    println!("data_start     {:x}", layout.data_start);
    println!("data_size      {:x}", layout.data_size);
    println!("bss_start      {:x}", layout.bss_start);
    println!("bss_size       {:x}", layout.bss_size);
    println!("reldata_start  {:x}", layout.reldata_start);
    println!("stack_size     {:x}", layout.stack_size);

    println!("");

    let mut buffer = Vec::<u8>::new();
    (&file)
        .take(layout.got_sym_start as u64 - std::mem::size_of::<LayoutHeader32>() as u64)
        .read_to_end(&mut buffer)
        .expect("read failed");

    for decoded in Disassembler::new(rv_isa::rv32, &buffer, header.header_size as u64) {
        println!("{:08x} {}", decoded.pc, format_inst(32, &decoded));
    }

    buffer = Vec::<u8>::new();
    file.read_to_end(&mut buffer).expect("read failed");
    println!("{:?}", buffer.hex_dump());
}

fn ss(file: &mut dyn Read, len: u64) -> String {
    let mut r = file.take(len);
    let mut buf = String::new();
    let _ = r.read_to_string(&mut buf);
    buf
}
fn hh(file: &mut dyn Read, size: u64) {
    let mut r2 = file.take(size);

    let mut i = 0;
    loop {
        let tlv = read_tbf_tlv(&mut r2).expect("ok");
        println!("type             {:x?}", tlv.tipe);
        println!("length           {:x?}", tlv.length);

        match tlv.tipe {
            TbfHeaderTypes::TbfHeaderMain => {
                let h = read_tbf_main(&mut r2).expect("ok");
                println!("init_fn_offset   {:x?}", h.init_fn_offset);
                println!("protected_size   {:x?}", h.protected_size);
                println!("minimum_ram_size {:x?}", h.minimum_ram_size);
            }
            TbfHeaderTypes::TbfHeaderPackageName => {
                let s = ss(&mut r2, tlv.length.into());
                println!("package name     {}", s);
            }
            _ => {}
        }

        println!("");

        i += 1;
        if i > 1 {
            break;
        }
    }

    // Burn down any part of the header we didn't consume.
    let mut buffer = Vec::new();
    let _ = r2.read_to_end(&mut buffer);
}
