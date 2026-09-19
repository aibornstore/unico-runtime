; Simple U30 assembly to test the tool

region 0 65536 1 1
function 0 1 0
  block 0
    const r0 u32 42
    ret r0
  end
end
entry 0