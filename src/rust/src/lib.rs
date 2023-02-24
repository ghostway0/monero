use pasta_curves::{group::ff::PrimeFieldBits, Fq};

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct FFIScalar([u64; 4]);

impl FFIScalar {
    pub fn from_field_element(element: Fq) -> Self {
        Self(element.to_le_bits().into_inner())
    }
}

#[no_mangle]
pub extern "C" fn librustmonero_mul(s1: *const FFIScalar, s2: *const FFIScalar, result: *mut FFIScalar) {
    let scalar1 = ffi_to_field_element(s1);
    let scalar2 = ffi_to_field_element(s2);

    let mul = scalar1 * scalar2;

    let result = unsafe { &mut *result };
    *result = FFIScalar::from_field_element(mul);
}

fn ffi_to_field_element(scalar: *const FFIScalar) -> Fq {
    unsafe {
        let bytes = scalar.as_ref().expect("Big trouble");
        std::mem::transmute::<FFIScalar, Fq>(*bytes)
    }
}

// #[no_mangle]
// pub extern "C" fn librustmonero_display(scalar: *const FFIScalar) {
//     let scalar = unsafe {
//         let scalar = Scalar::from_raw(*scalar);
//         scalar
//     };

//     println!("{:?}", scalar);
// }
