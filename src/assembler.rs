//! UNICO U30 Assembler
//!
//! This module provides functionality to assemble U30 assembly text into binary modules.
//!
//! Assembly format:
//! - Lines starting with `;` are comments
//! - `region <id> <size> <readable> <writable>` declares a memory region
//! - `table <id> <targets...>` declares a jump table
//! - `function <param_count> <result_count> <entry_block>` declares a function
//! - `block <id>` starts a block
//! - `end` ends a block or function
//! - `entry <function_index>` sets the entry function
//! - Instructions: `const`, `binary`, `ret`

use crate::error::{Error, Result};
use crate::ir::{U30BinaryOp, U30Block, U30Function, U30Module, U30Op, U30Terminator, U30Type, U30Value};

/// Parse a type annotation (e.g., "u32", "f64", "bool") into U30Type
fn parse_type(s: &str) -> Result<U30Type> {
    match s {
        "bool" => Ok(U30Type::Bool),
        "u8" => Ok(U30Type::U8),
        "u16" => Ok(U30Type::U16),
        "u32" => Ok(U30Type::U32),
        "u64" => Ok(U30Type::U64),
        "f32" => Ok(U30Type::F32),
        "f64" => Ok(U30Type::F64),
        _ => Err(Error::Generic(format!("Invalid type: {}", s))),
    }
}

/// Parse a register specifier (e.g., "r0", "r127") into register index
fn parse_register(s: &str) -> Result<u32> {
    if !s.starts_with('r') {
        return Err(Error::Generic(format!("Unknown register: {}", s)));
    }
    
    let num_str = &s[1..];
    num_str
        .parse()
        .map_err(|_| Error::Generic(format!("Unknown register: {}", s)))
}

/// Parse a binary operation string into U30BinaryOp
fn parse_binary_op(s: &str) -> Result<U30BinaryOp> {
    match s {
        "add_u32" => Ok(U30BinaryOp::AddWrapU32),
        "add_u64" => Ok(U30BinaryOp::AddWrapU64),
        "sub_u32" => Ok(U30BinaryOp::SubWrapU32),
        "sub_u64" => Ok(U30BinaryOp::SubWrapU64),
        "mul_u32" => Ok(U30BinaryOp::MulWrapU32),
        "mul_u64" => Ok(U30BinaryOp::MulWrapU64),
        "div_u32" => Ok(U30BinaryOp::DivU32),
        "div_u64" => Ok(U30BinaryOp::DivU64),
        "rem_u32" => Ok(U30BinaryOp::RemU32),
        "rem_u64" => Ok(U30BinaryOp::RemU64),
        "and_u8" => Ok(U30BinaryOp::AndU8),
        "or_u8" => Ok(U30BinaryOp::OrU8),
        "xor_u8" => Ok(U30BinaryOp::XorU8),
        "shl_u32" => Ok(U30BinaryOp::ShlU32),
        "shl_u64" => Ok(U30BinaryOp::ShlU64),
        "shr_u32" => Ok(U30BinaryOp::ShrU32),
        "shr_u64" => Ok(U30BinaryOp::ShrU64),
        "eq" => Ok(U30BinaryOp::Eq),
        "lt_u32" => Ok(U30BinaryOp::LtU64),
        "lt_u64" => Ok(U30BinaryOp::LtU64),
        "gt_u32" => Ok(U30BinaryOp::GtU64),
        "gt_u64" => Ok(U30BinaryOp::GtU64),
        "ge_u32" => Ok(U30BinaryOp::GeU64),
        "ge_u64" => Ok(U30BinaryOp::GeU64),
        "le_u32" => Ok(U30BinaryOp::LeU64),
        "le_u64" => Ok(U30BinaryOp::LeU64),
        "min_u32" => Ok(U30BinaryOp::MinU32),
        "min_u64" => Ok(U30BinaryOp::MinU64),
        "max_u32" => Ok(U30BinaryOp::MaxU32),
        "max_u64" => Ok(U30BinaryOp::MaxU64),
        _ => Err(Error::Generic(format!("Invalid binary operation: {}", s))),
    }
}

/// Parse an assembly line and return tokens
fn tokenize_line(line: &str) -> Vec<String> {
    let line = line.split(';').next().unwrap_or("");
    line.split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Parse a constant value based on its type
fn parse_constant(s: &str, ty: &U30Type) -> Result<U30Value> {
    match ty {
        U30Type::Bool => match s {
            "true" => Ok(U30Value::Bool(true)),
            "false" => Ok(U30Value::Bool(false)),
            _ => Err(Error::Generic(format!("Invalid boolean constant: {}", s))),
        },
        U30Type::U8 => s
            .parse::<u8>()
            .map(U30Value::U8)
            .map_err(|_| Error::Generic(format!("Invalid u8 constant: {}", s))),
        U30Type::U16 => s
            .parse::<u16>()
            .map(U30Value::U16)
            .map_err(|_| Error::Generic(format!("Invalid u16 constant: {}", s))),
        U30Type::U32 => s
            .parse::<u32>()
            .map(U30Value::U32)
            .map_err(|_| Error::Generic(format!("Invalid u32 constant: {}", s))),
        U30Type::U64 => s
            .parse::<u64>()
            .map(U30Value::U64)
            .map_err(|_| Error::Generic(format!("Invalid u64 constant: {}", s))),
        U30Type::F32 => s
            .parse::<f32>()
            .map(U30Value::F32)
            .map_err(|_| Error::Generic(format!("Invalid f32 constant: {}", s))),
        U30Type::F64 => s
            .parse::<f64>()
            .map(U30Value::F64)
            .map_err(|_| Error::Generic(format!("Invalid f64 constant: {}", s))),
    }
}

/// Parse assembly text into U30Module
pub fn assemble(asm: &str) -> Result<U30Module> {
    let mut regions = Vec::new();
    let mut tables = Vec::new();
    let mut functions = Vec::new();
    let mut entry_function = 0;
    
    let mut current_func: Option<FunctionBuilder> = None;
    let mut current_block: Option<BlockBuilder> = None;
    
    for (line_num, line) in asm.lines().enumerate() {
        let line_num = line_num + 1;
        let tokens = tokenize_line(line);
        
        if tokens.is_empty() {
            continue;
        }
        
        match tokens[0].as_str() {
            "region" => {
                if tokens.len() != 5 {
                    return Err(Error::Generic(format!(
                        "line {}: region requires 4 args, got {}",
                        line_num,
                        tokens.len() - 1
                    )));
                }
                
                let id = tokens[1]
                    .parse()
                    .map_err(|_| Error::Generic(format!("line {}: Invalid region id", line_num)))?;
                let size = tokens[2]
                    .parse()
                    .map_err(|_| Error::Generic(format!("line {}: Invalid region size", line_num)))?;
                let readable = tokens[3]
                    .parse::<u8>()
                    .map_err(|_| Error::Generic(format!("line {}: Invalid readable flag", line_num)))?
                    != 0;
                let writable = tokens[4]
                    .parse::<u8>()
                    .map_err(|_| Error::Generic(format!("line {}: Invalid writable flag", line_num)))?
                    != 0;
                
                regions.push(crate::ir::U30RegionDecl {
                    id,
                    size,
                    readable,
                    writable,
                    initial: vec![0; size],
                });
            }
            
            "table" => {
                if tokens.len() < 3 {
                    return Err(Error::Generic(format!(
                        "line {}: table requires id and at least one target",
                        line_num
                    )));
                }
                
                let id = tokens[1]
                    .parse()
                    .map_err(|_| Error::Generic(format!("line {}: Invalid table id", line_num)))?;
                let targets: Result<Vec<_>> = tokens[2..]
                    .iter()
                    .map(|t| {
                        t.parse().map_err(|_| {
                            Error::Generic(format!("line {}: Invalid table target: {}", line_num, t))
                        })
                    })
                    .collect();
                
                tables.push(crate::ir::U30TableDecl {
                    id,
                    targets: targets?,
                });
            }
            
            "function" => {
                if tokens.len() != 4 {
                    return Err(Error::Generic(format!(
                        "line {}: function requires 3 args: params, results, entry_block",
                        line_num
                    )));
                }
                
                if let Some(mut func) = current_func.take() {
                    if let Some(block) = current_block.take() {
                        func.blocks.push(block.build()?);
                    }
                    functions.push(func.build()?);
                }
                
                let param_count = tokens[1].parse().map_err(|_| {
                    Error::Generic(format!("line {}: Invalid param count", line_num))
                })?;
                let result_count = tokens[2].parse().map_err(|_| {
                    Error::Generic(format!("line {}: Invalid result count", line_num))
                })?;
                let entry_block = tokens[3].parse().map_err(|_| {
                    Error::Generic(format!("line {}: Invalid entry block", line_num))
                })?;
                
                current_func = Some(FunctionBuilder::new(param_count, result_count, entry_block));
            }
            
            "block" => {
                if tokens.len() != 2 {
                    return Err(Error::Generic(format!(
                        "line {}: block requires 1 arg: block_id",
                        line_num
                    )));
                }
                
                if let Some(ref mut func) = current_func {
                    if let Some(block) = current_block.take() {
                        func.blocks.push(block.build()?);
                    }
                }
                
                let block_id = tokens[1].parse().map_err(|_| {
                    Error::Generic(format!("line {}: Invalid block id", line_num))
                })?;
                
                current_block = Some(BlockBuilder::new(block_id));
            }
            
            "end" => {
                if tokens.len() == 1 {
                    if let Some(ref mut func) = current_func {
                        if let Some(block) = current_block.take() {
                            func.blocks.push(block.build()?);
                        }
                    }
                } else if tokens.len() == 2 && tokens[1] == "function" {
                    if let Some(mut func) = current_func.take() {
                        if let Some(block) = current_block.take() {
                            func.blocks.push(block.build()?);
                        }
                        functions.push(func.build()?);
                    }
                } else if tokens.len() == 2 && tokens[1] == "block" {
                    if let Some(ref mut func) = current_func {
                        if let Some(block) = current_block.take() {
                            func.blocks.push(block.build()?);
                        }
                    }
                } else {
                    return Err(Error::Generic(format!(
                        "line {}: Invalid end directive",
                        line_num
                    )));
                }
            }
            
            "entry" => {
                if tokens.len() != 2 {
                    return Err(Error::Generic(format!(
                        "line {}: entry requires 1 arg: function_index",
                        line_num
                    )));
                }
                
                entry_function = tokens[1].parse().map_err(|_| {
                    Error::Generic(format!("line {}: Invalid function index", line_num))
                })?;
            }
            
            "const" => {
                if tokens.len() != 4 {
                    return Err(Error::Generic(format!(
                        "line {}: const requires 3 args: reg, type, value",
                        line_num
                    )));
                }
                
                let reg = parse_register(&tokens[1])?;
                let ty = parse_type(&tokens[2])?;
                let value = parse_constant(&tokens[3], &ty)?;
                
                if let Some(ref mut block) = current_block {
                    block.add_op(U30Op::Const { dst: reg, value });
                }
            }
            
            "binary" => {
                if tokens.len() != 5 {
                    return Err(Error::Generic(format!(
                        "line {}: binary requires 4 args: reg, op, reg_a, reg_b",
                        line_num
                    )));
                }
                
                let dst = parse_register(&tokens[1])?;
                let op = parse_binary_op(&tokens[2])?;
                let a = parse_register(&tokens[3])?;
                let b = parse_register(&tokens[4])?;
                
                if let Some(ref mut block) = current_block {
                    block.add_op(U30Op::Binary { dst, op, a, b });
                }
            }
            
            "ret" => {
                if tokens.len() != 2 {
                    return Err(Error::Generic(format!(
                        "line {}: ret requires 1 arg: reg",
                        line_num
                    )));
                }
                
                let reg = parse_register(&tokens[1])?;
                
                if let Some(ref mut block) = current_block {
                    block.set_terminator(U30Terminator::Ret {
                        values: vec![reg],
                    });
                }
            }
            
            _ => {
                return Err(Error::Generic(format!(
                    "line {}: Unknown directive or instruction '{}'",
                    line_num, tokens[0]
                )));
            }
        }
    }
    
    if let Some(mut func) = current_func {
        if let Some(block) = current_block.take() {
            func.blocks.push(block.build()?);
        }
        functions.push(func.build()?);
    }
    
    Ok(U30Module {
        regions,
        tables,
        functions,
        entry_function,
    })
}

/// Helper struct for building a function during assembly
struct FunctionBuilder {
    params: Vec<U30Type>,
    results: Vec<U30Type>,
    entry_block: usize,
    blocks: Vec<U30Block>,
}

impl FunctionBuilder {
    fn new(param_count: usize, result_count: usize, entry_block: usize) -> Self {
        // For now, all params/results are u32
        let param_type = U30Type::U32;
        let result_type = U30Type::U32;
        
        Self {
            params: vec![param_type; param_count],
            results: vec![result_type; result_count],
            entry_block,
            blocks: Vec::new(),
        }
    }
    
    fn build(self) -> Result<U30Function> {
        Ok(U30Function {
            params: self.params,
            results: self.results,
            blocks: self.blocks,
            entry_block: self.entry_block,
        })
    }
}

/// Helper struct for building a block during assembly
struct BlockBuilder {
    id: usize,
    ops: Vec<U30Op>,
    terminator: Option<U30Terminator>,
}

impl BlockBuilder {
    fn new(id: usize) -> Self {
        Self {
            id,
            ops: Vec::new(),
            terminator: None,
        }
    }
    
    fn add_op(&mut self, op: U30Op) {
        self.ops.push(op);
    }
    
    fn set_terminator(&mut self, term: U30Terminator) {
        self.terminator = Some(term);
    }
    
    fn build(self) -> Result<U30Block> {
        Ok(U30Block {
            ops: self.ops,
            terminator: self.terminator.ok_or_else(|| {
                Error::Generic(format!("Block {} missing terminator", self.id))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simple_assembly() {
        let asm = r#"
            region 0 65536 1 1
            function 1 1 0
              block 0
                const r0 u32 42
                const r1 u32 10
                binary r2 add_u32 r0 r1
                ret r2
              end
            end
            entry 0
        "#;
        
        let module = assemble(asm).expect("Failed to assemble");
        assert_eq!(module.regions.len(), 1);
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.entry_function, 0);
        
        let func = &module.functions[0];
        assert_eq!(func.params.len(), 1);
        assert_eq!(func.results.len(), 1);
        assert_eq!(func.blocks.len(), 1);
        
        let block = &func.blocks[0];
        assert_eq!(block.ops.len(), 3);
        assert!(matches!(&block.ops[0], U30Op::Const { dst: 0, value: U30Value::U32(42) }));
        assert!(matches!(&block.ops[1], U30Op::Const { dst: 1, value: U30Value::U32(10) }));
        assert!(matches!(
            &block.ops[2],
            U30Op::Binary {
                dst: 2,
                op: U30BinaryOp::AddWrapU32,
                a: 0,
                b: 1
            }
        ));
        assert!(matches!(&block.terminator, U30Terminator::Ret { values } if values == &vec![2]));
    }
    
    #[test]
    fn test_assemble_and_encode() {
        let asm = r#"
            region 0 65536 1 1
            function 0 1 0
              block 0
                const r0 u32 123
                ret r0
              end
            end
            entry 0
        "#;
        
        let module = assemble(asm).expect("Failed to assemble");
        let binary = crate::ser::encode(&module);
        
        let decoded = crate::ser::decode(&binary).expect("Failed to decode");
        assert_eq!(module.regions.len(), decoded.regions.len());
        assert_eq!(module.functions.len(), decoded.functions.len());
        assert_eq!(module.entry_function, decoded.entry_function);
    }

    // ---- parse_type error cases ----
    #[test]
    fn test_parse_type_invalid() {
        let r = parse_type("invalid");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid type"));
    }

    // ---- parse_register error cases ----
    #[test]
    fn test_parse_register_no_r_prefix() {
        let r = parse_register("x0");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown register"));
    }

    #[test]
    fn test_parse_register_invalid_number() {
        let r = parse_register("rabc");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown register"));
    }

    // ---- parse_binary_op error cases ----
    #[test]
    fn test_parse_binary_op_invalid() {
        let r = parse_binary_op("unknown_op");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid binary operation"));
    }

    // ---- parse_constant error cases ----
    #[test]
    fn test_parse_constant_invalid_bool() {
        let r = parse_constant("maybe", &U30Type::Bool);
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_constant_invalid_u8() {
        let r = parse_constant("256", &U30Type::U8);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid u8 constant"));
    }

    #[test]
    fn test_parse_constant_invalid_u16() {
        let r = parse_constant("999999", &U30Type::U16);
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_constant_invalid_u32() {
        let r = parse_constant("not_a_number", &U30Type::U32);
        assert!(r.is_err());
    }

    #[test]
    fn test_parse_constant_invalid_f32() {
        let r = parse_constant("not_a_float", &U30Type::F32);
        assert!(r.is_err());
    }

    // ---- tokenize_line ----
    #[test]
    fn test_tokenize_line_comment_only() {
        let r = tokenize_line("; this is a comment");
        assert!(r.is_empty());
    }

    #[test]
    fn test_tokenize_line_empty() {
        let r = tokenize_line("");
        assert!(r.is_empty());
    }

    #[test]
    fn test_tokenize_line_with_comment() {
        let r = tokenize_line("const r0 u32 42 ; this is inline comment");
        assert_eq!(r.len(), 4);
        assert_eq!(r[0], "const");
        assert_eq!(r[1], "r0");
        assert_eq!(r[2], "u32");
        assert_eq!(r[3], "42");
    }

    #[test]
    fn test_tokenize_line_whitespace_only() {
        let r = tokenize_line("   \t  ");
        assert!(r.is_empty());
    }

    // ---- Assembler error cases ----
    #[test]
    fn test_assemble_region_wrong_arg_count() {
        let r = assemble("region 0 65536 1");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("region requires 4 args"));
    }

    #[test]
    fn test_assemble_region_invalid_id() {
        let r = assemble("region abc 65536 1 1");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid region id"));
    }

    #[test]
    fn test_assemble_region_invalid_readable() {
        let r = assemble("region 0 65536 not_a_flag 1");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid readable flag"));
    }

    #[test]
    fn test_assemble_function_wrong_arg_count() {
        let r = assemble("region 0 65536 1 1\nfunction 1 0");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("function requires 3 args"));
    }

    #[test]
    fn test_assemble_function_invalid_param_count() {
        let r = assemble("region 0 65536 1 1\nfunction abc 0 0");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid param count"));
    }

    #[test]
    fn test_assemble_block_wrong_arg_count() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0 1");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("block requires 1 arg"));
    }

    #[test]
    fn test_assemble_block_invalid_id() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock abc");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid block id"));
    }

    #[test]
    fn test_assemble_const_wrong_arg_count() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nconst r0 u32");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("const requires 3 args"));
    }

    #[test]
    fn test_assemble_const_invalid_type() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nconst r0 nonexistent 42");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid type"));
    }

    #[test]
    fn test_assemble_binary_wrong_arg_count() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nbinary r0 add_u32 r1");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("binary requires 4 args"));
    }

    #[test]
    fn test_assemble_binary_invalid_op() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nbinary r0 bad_op r1 r2");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid binary operation"));
    }

    #[test]
    fn test_assemble_binary_invalid_dst_register() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nbinary x0 add_u32 r1 r2");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown register"));
    }

    #[test]
    fn test_assemble_ret_wrong_arg_count() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nret");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("ret requires 1 arg"));
    }

    #[test]
    fn test_assemble_ret_invalid_register() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nret xyz");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown register"));
    }

    #[test]
    fn test_assemble_entry_wrong_arg_count() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nret r0\nend\nentry");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("entry requires 1 arg"));
    }

    #[test]
    fn test_assemble_entry_invalid_index() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nret r0\nend\nentry abc");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid function index"));
    }

    #[test]
    fn test_assemble_unknown_directive() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nret r0\nend\nunknown_directive 123");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Unknown directive"));
    }

    #[test]
    fn test_assemble_end_invalid_directive() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nret r0\nend invalid");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid end directive"));
    }

    #[test]
    fn test_assemble_block_missing_terminator() {
        let r = assemble("region 0 65536 1 1\nfunction 0 0 0\nblock 0\nconst r0 u32 42\nend");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("missing terminator"));
    }

    // ---- Happy path extensions ----
    #[test]
    fn test_assemble_multiple_functions() {
        let asm = r#"
            region 0 65536 1 1
            function 0 1 0
              block 0
                const r0 u32 1
                ret r0
              end
            end
            function 0 1 0
              block 0
                const r0 u32 2
                ret r0
              end
            end
            entry 0
        "#;
        let module = assemble(asm).expect("Failed to assemble");
        assert_eq!(module.functions.len(), 2);
        assert_eq!(module.entry_function, 0);
    }

    #[test]
    fn test_assemble_multiple_blocks() {
        let asm = r#"
            region 0 65536 1 1
            function 0 1 0
              block 0
                const r0 u32 1
                ret r0
              end
              block 1
                const r0 u32 2
                ret r0
              end
            end
            entry 0
        "#;
        let module = assemble(asm).expect("Failed to assemble");
        assert_eq!(module.functions[0].blocks.len(), 2);
    }

    #[test]
    fn test_assemble_with_table() {
        let asm = r#"
            region 0 65536 1 1
            table 0 1 2 3
            function 0 1 0
              block 0
                const r0 u32 1
                ret r0
              end
            end
            entry 0
        "#;
        let module = assemble(asm).expect("Failed to assemble");
        assert_eq!(module.tables.len(), 1);
        assert_eq!(module.tables[0].id, 0);
        assert_eq!(module.tables[0].targets, vec![1, 2, 3]);
    }

    #[test]
    fn test_assemble_table_invalid_id() {
        let r = assemble("region 0 65536 1 1\ntable abc 1 2 3");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid table id"));
    }

    #[test]
    fn test_assemble_table_invalid_target() {
        let r = assemble("region 0 65536 1 1\ntable 0 1 abc 3");
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("Invalid table target"));
    }

    #[test]
    fn test_assemble_table_min_args() {
        let asm = r#"
            region 0 65536 1 1
            table 0 1
            function 0 1 0
              block 0
                const r0 u32 0
                ret r0
              end
            end
            entry 0
        "#;
        let module = assemble(asm).expect("Failed to assemble");
        assert_eq!(module.tables.len(), 1);
        assert_eq!(module.tables[0].targets, vec![1]);
    }

    #[test]
    fn test_assemble_all_binary_ops() {
        let ops = [
            ("add_u32", U30BinaryOp::AddWrapU32),
            ("add_u64", U30BinaryOp::AddWrapU64),
            ("sub_u32", U30BinaryOp::SubWrapU32),
            ("sub_u64", U30BinaryOp::SubWrapU64),
            ("mul_u32", U30BinaryOp::MulWrapU32),
            ("mul_u64", U30BinaryOp::MulWrapU64),
            ("div_u32", U30BinaryOp::DivU32),
            ("div_u64", U30BinaryOp::DivU64),
            ("rem_u32", U30BinaryOp::RemU32),
            ("rem_u64", U30BinaryOp::RemU64),
            ("and_u8", U30BinaryOp::AndU8),
            ("or_u8", U30BinaryOp::OrU8),
            ("xor_u8", U30BinaryOp::XorU8),
            ("shl_u32", U30BinaryOp::ShlU32),
            ("shl_u64", U30BinaryOp::ShlU64),
            ("shr_u32", U30BinaryOp::ShrU32),
            ("shr_u64", U30BinaryOp::ShrU64),
            ("eq", U30BinaryOp::Eq),
            ("lt_u32", U30BinaryOp::LtU64),
            ("lt_u64", U30BinaryOp::LtU64),
            ("gt_u32", U30BinaryOp::GtU64),
            ("gt_u64", U30BinaryOp::GtU64),
            ("ge_u32", U30BinaryOp::GeU64),
            ("ge_u64", U30BinaryOp::GeU64),
            ("le_u32", U30BinaryOp::LeU64),
            ("le_u64", U30BinaryOp::LeU64),
            ("min_u32", U30BinaryOp::MinU32),
            ("min_u64", U30BinaryOp::MinU64),
            ("max_u32", U30BinaryOp::MaxU32),
            ("max_u64", U30BinaryOp::MaxU64),
        ];
        for (name, expected_op) in ops {
            let asm = format!(r#"
                region 0 65536 1 1
                function 0 1 0
                  block 0
                    const r0 u32 1
                    const r1 u32 2
                    binary r2 {} r0 r1
                    ret r2
                  end
                end
                entry 0
            "#, name);
            let module = assemble(&asm).expect(&format!("Failed for op: {}", name));
            if let U30Op::Binary { op, .. } = &module.functions[0].blocks[0].ops[2] {
                assert_eq!(*op, expected_op, "Mismatch for op: {}", name);
            } else {
                panic!("Expected Binary op for: {}", name);
            }
        }
    }

    #[test]
    fn test_assemble_all_types() {
        let types = [
            ("bool", "true", U30Type::Bool),
            ("u8", "42", U30Type::U8),
            ("u16", "1000", U30Type::U16),
            ("u32", "123456", U30Type::U32),
            ("u64", "9999999999", U30Type::U64),
            ("f32", "3.14", U30Type::F32),
            ("f64", "2.71828", U30Type::F64),
        ];
        for (name, value, _expected_ty) in types {
            let asm = format!(r#"
                region 0 65536 1 1
                function 0 1 0
                  block 0
                    const r0 {} {}
                    ret r0
                  end
                end
                entry 0
            "#, name, value);
            let r = assemble(&asm);
            if r.is_err() {
                panic!("Failed for type {}: {}", name, r.unwrap_err());
            }
        }
    }

    #[test]
    fn test_assemble_empty_lines_ignored() {
        let asm = "\n\n   \n; comment\n\nregion 0 65536 1 1\n\nfunction 0 1 0\n\nblock 0\n\nconst r0 u32 0\n\nret r0\n\nend\n\nentry 0\n";
        let module = assemble(asm).expect("Failed to assemble with empty lines");
        assert_eq!(module.regions.len(), 1);
    }
}