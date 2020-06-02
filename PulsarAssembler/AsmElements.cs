using Antlr4.Runtime.Misc;
using Antlr4.Runtime.Tree;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.Design.Serialization;
using System.IO;
using System.Numerics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PulsarAssembler
{
    public enum IntegerType
    {
        Decimal,
        Hexadecimal,
        Binary,
    }

    public enum Endianness
    {
        LittleEndian,
        BigEndian,
    }

    public enum MnemonicType
    {
        Invalid,
        Nop,
        Cpyzx,
        Cpysx,
        Syscall,
        Chngmode,
        Smcodst,
        Smcodend,
        Sysid,
        Int,
        Ret,
        Allocvars,
        Dbgint,
        Getretptr,
        Setretptr,
        Clrst,
        Getcdptr,
        Movzx,
        Movsx,
        Loadctx,
        Savectx,
        Getctxsz,
        Jmp,
        Fwcall,
        Jmpusr,
        Callnat,
        Jmpnat,
        Rdsysreg,
        Wrsysreg,
        Rdinforeg,
        Rdport,
        Wrport,
        Prrdstatreg,
        Fbdint,
        Alwint,
        Getintflag,
        Iret,
        Call,
        Zero,
        Fill,
        Not,
        Neg,
        Shr,
        Shl,
        Sar,
        Rtr,
        Rtl,
        Cpy,
        Incr,
        Decr,
        Push,
        Pop,
        Alignleft,
        Alignright,
        Getfromd,
        Setfromd,
        Rdtcks,
        Getip,
        Getstreg,
        Setstreg,
        Rdstatreg,
        Ftrunc,
        Ftontte,
        Ftontafz,
        Frotopinf,
        Frotominf,
        Add,
        Sub,
        Mul,
        Div,
        Idiv,
        And,
        Or,
        Xor,
        Nor,
        Addo,
        Subo,
        Mulo,
        Cmp,
        Crsvptr,
        Getbit,
        Setbit,
        Invbit,
        Jumpif,
        Fadd,
        Fsub,
        Fmul,
        Fdiv,
        Restreg,
        Strreg,
        Getcaptr,
        Rem,
        Irem,
        Nand,
        Adds,
        Subs,
        Muls,
        Addss,
        Subss,
        Mulss,
        Getefad,
    }

    public enum InstructionTypeSpecifier
    {
        I8,
        I16,
        I32,
        I64,
        I128,
        I256,
        A8,
        A16,
        A32,
        A64,
        A128,
        A256,
        Unaligned,
    }

    public enum InstructionConditionTokenType
    {
        Zer,
        Nzer,
        Negative,
        Positive,
        Carry,
        Ncarry,
        Ovf,
        Novf,
        Equal,
        Nequal,
        Uless,
        Ugreatereq,
        Ulesseq,
        Ugreater,
        Sless,
        Sgreatereq,
        Slesseq,
        Sgreater,
        Parity,
        ParityEven,
        Nparity,
        ParityOdd,
        Halfcarry,
        Nhalfcarry,
        Umax,
        Numax,
        Umin,
        Numin,
        Minusone,
        Nminusone,
        Smax,
        Nsmax,
        Smin,
        Nsmin,
        One,
        Notone,
        True,
        False,
    }

    public enum RegisterKind
    {
        GeneralPurpose,
        System,
        Informational,
    }

    public enum OperandType
    {
        Immediate,
        Register,
        MemoryImmediate,
        Indirect,
        Local,
        BaseWithImmediateOffset,
        BaseWithRegisterOffset,
        Relative,
        Identifier,
        IdentifierOffset,

        SystemRegister,
        InfoRegister,
    }

    public enum InstrPlane
    {
        Basic,
        Priv,
        Op0,
        Op1,
        Op1Imm,
        Op2,
        Op2Imm,
        Op3,
        Op3Imm,
    }

    interface IAsmElement : IEnumerable<IReadOnlyList<byte>>, IReadOnlyList<IAsmElement>
    {
        string Text { get; }
        int TotalBytesCount { get; }

        string ToString();
    }

    enum DataWidth
    {
        I8,
        I16,
        I32,
        I64,
    }

    class DataElement : PulsarAsmGrammarBaseListener, IAsmElement
    {
        public DataElement(PulsarAsmGrammarParser.Data_definition_statementContext ctx, Endianness currentEndianness)
        {
            Endianness = currentEndianness;
            Width = InstructionEncoding.GetDataAddressWidth(ctx.DATA_TYPE_SPECIFIER().GetText());
            if (ctx.data_identifier().IDENTIFIER() != null)
            {
                SetId(ctx.data_identifier().GetText());
            }
            Text = ctx.GetText();
        }

        public string Text { get; private set; }

        private void AddDataElement(PulsarAsmGrammarParser.Data_definitionContext ctx)
        {
            if (ctx.TEXT_STRING() != null)
            {
                AddString(ctx.TEXT_STRING().GetText());
            }
            else if (ctx.integer() != null)
            {
                AddInteger(ctx.integer().GetText());
            }
        }

        public override void EnterData_definition([NotNull] PulsarAsmGrammarParser.Data_definitionContext context)
        {
            AddDataElement(context);
        }

        private void SetId(string id)
        {
            Id = id;
        }

        private void AddInteger(string text)
        {
            ulong value = InstructionEncoding.ParseInteger(text);
            byte[] data = AsByteArray(value, Width, Endianness);
            Bytes.Add(data);
            TotalBytesCount += data.Length;
        }

        private void AddString(string str)
        {
            List<byte> bytesToAdd = new List<byte>();
            str = str[1..^1];
            str = Regex.Unescape(str);
            if (Width == DataWidth.I8)
            {
                bytesToAdd.AddRange(Encoding.UTF8.GetBytes(str));
            }
            else
            {
                switch (Width)
                {
                    case DataWidth.I16:
                        foreach (char ch in str)
                        {
                            byte[] chBytes = InstructionEncoding.AdjustEndianness(ch, Endianness);
                            bytesToAdd.AddRange(chBytes);
                        }
                        return;
                    case DataWidth.I32:
                        byte[] tmpBytes = Encoding.UTF32.GetBytes(str);
                        for (int i = 0; i < tmpBytes.Length / 4; i += 4)
                        {
                            Span<byte> char32 = tmpBytes.AsSpan(i, 4);
                            char32.Reverse();
                        }
                        bytesToAdd.AddRange(tmpBytes);
                        break;
                    default:
                        throw new InvalidOperationException("Strings of width " + Width + " are not supported");
                }
            }
            TotalBytesCount += bytesToAdd.Count;
            Bytes.Add(bytesToAdd);
        }
        public Endianness Endianness { get; }
        public DataWidth Width { get; private set; }
        public string Id { get; private set; }
        public IList<IReadOnlyList<byte>> Bytes { get; } = new List<IReadOnlyList<byte>>();
        public int TotalBytesCount { get; private set; } = 0;

        public int Count => 0;

        public IAsmElement this[int index] => throw new InvalidOperationException();

        private static byte[] AsByteArray(ulong intValue, DataWidth width, Endianness endianness)
        {
            switch (width)
            {
                case DataWidth.I8:
                    byte b = (byte)intValue;
                    return new byte[] { b };
                case DataWidth.I16:
                    ushort s = (ushort)intValue;
                    return InstructionEncoding.AdjustEndianness(s, endianness);
                case DataWidth.I32:
                    uint i = (uint)intValue;
                    return InstructionEncoding.AdjustEndianness(i, endianness);
                case DataWidth.I64:
                    return InstructionEncoding.AdjustEndianness(intValue, endianness);
                default:
                    throw new InvalidOperationException("Invalid width type: " + width);
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        public IEnumerator<IReadOnlyList<byte>> GetEnumerator()
        {
            foreach (var list in Bytes)
            {
                yield return list;
            }
        }

        IEnumerator<IAsmElement> IEnumerable<IAsmElement>.GetEnumerator()
        {
            yield break;
        }
    }

    abstract class Operand
    {
        public abstract OperandType Type { get; }
        public abstract string Text { get; }
        public override string ToString()
        {
            return Text;
        }
    }

    abstract class Immediate : Operand
    {
        public bool Sign { get; private set; }
        public long SignedVal { get => (long)UnsignedVal; set => UnsignedVal = (ulong)value; }
        public ulong UnsignedVal { get; set; }
        public abstract string OperandId { get; }
        public virtual void SetValue(long val)
        {
            SignedVal = val;
            Sign = true;
        }
        public virtual void SetValue(ulong val)
        {
            UnsignedVal = val;
            Sign = false;
        }
    }

    class OffsetImmediate : Immediate
    {
        public OffsetImmediate(string id)
        {
            operandId = id;
        }

        public override OperandType Type => valueSet ? OperandType.Immediate : OperandType.IdentifierOffset;
        private string operandId;
        public override string Text => valueSet ? SignedVal.ToString() : "OFFSET " + OperandId;
        public override string OperandId { get => operandId; }
        public void SetOperandId(string id)
        {
            operandId = id;
        }

        bool valueSet = false;
        public override void SetValue(long val)
        {
            base.SetValue(val);
            valueSet = true;
        }

        public override void SetValue(ulong val)
        {
            base.SetValue(val);
            valueSet = true;
        }
    }

    class IntegerImmediate : Immediate
    {
        public IntegerImmediate(ulong data)
        {
            SetValue(data);
        }

        public IntegerImmediate(long data)
        {
            SetValue(data);
        }

        public override OperandType Type => OperandType.Immediate;
        public override string OperandId => null;
        public override string Text => Sign ? SignedVal.ToString() : UnsignedVal.ToString();
    }

    class MemoryImmediate : Immediate
    {
        public MemoryImmediate(ulong addr)
        {
            UnsignedVal = addr;
        }

        public override string OperandId => null;

        public override OperandType Type => OperandType.MemoryImmediate;

        public override string Text => $"[{UnsignedVal}]";
    }

    abstract class AnyRegisterOperand : Operand
    {
        protected AnyRegisterOperand(RegisterKind kind, byte num)
        {
            RegisterInfo = (kind, num);
        }

        public (RegisterKind, byte) RegisterInfo { get; }

        protected static string GetRegStr(RegisterKind kind, byte number)
        {
            return kind switch
            {
                RegisterKind.GeneralPurpose => "R" + number,
                RegisterKind.Informational => "IR" + number,
                RegisterKind.System => "SR" + number,
                _ => throw new InvalidOperationException("Wrong register type: " + kind),
            };
        }
    }

    class RegisterOperand : AnyRegisterOperand
    {
        public RegisterOperand(RegisterKind kind, byte regNumber)
            : base(kind, regNumber)
        {
        }

        public override OperandType Type => OperandType.Register;
        public override string Text => GetRegStr(RegisterInfo.Item1, RegisterInfo.Item2);
    }

    class RegisterIndirectOperand : AnyRegisterOperand
    {
        public RegisterIndirectOperand(byte regNumber)
            : base(RegisterKind.GeneralPurpose, regNumber)
        {
        }

        public override OperandType Type => OperandType.Indirect;
        public override string Text => $"[{GetRegStr(RegisterInfo.Item1, RegisterInfo.Item2)}]";
    }

    class BaseWithImmediateOffset : AnyRegisterOperand
    {
        public BaseWithImmediateOffset(byte regNumber, long offset)
            : base(RegisterKind.GeneralPurpose, regNumber)
        {
            Offset = offset;
        }

        public override OperandType Type => OperandType.BaseWithImmediateOffset;
        public long Offset { get; }

        public override string Text => $"[{GetRegStr(RegisterInfo.Item1, RegisterInfo.Item2)} {(Offset < 0 ? "- " + (-Offset).ToString() : "+ " + Offset.ToString())}]";
    }

    class BaseWithRegisterOffset : AnyRegisterOperand
    {
        public BaseWithRegisterOffset(byte regNumber, byte second)
            : base(RegisterKind.GeneralPurpose, regNumber)
        {
            SecondRegNumber = second;
        }

        public override OperandType Type => OperandType.BaseWithRegisterOffset;

        public byte SecondRegNumber { get; private set; }
        public override string Text => $"[{GetRegStr(RegisterInfo.Item1, RegisterInfo.Item2)} {(Minus ? "-" : "+")} {GetRegStr(RegisterKind.GeneralPurpose, SecondRegNumber)}]";

        public bool Minus { get; private set; }
    }

    abstract class RelativeOperand : Operand
    {
        public override OperandType Type => OperandType.Relative;
        public override string Text => "~" + Offset;
        public abstract long Offset { get; set; }
    }

    class ConcreteRelativeOperand : RelativeOperand
    {
        public ConcreteRelativeOperand(long offset)
        {
            Offset = offset;
        }

        public override long Offset { get; set; }
    }

    class DataOperand : RelativeOperand
    {
        public DataOperand(string identifier)
        {
            Identifier = identifier;
        }

        private OperandType type = OperandType.Identifier;
        public override OperandType Type { get => type; }

        public string Identifier { get; }
        private bool offsetSet = false;
        private long offset;
        public override long Offset
        {
            get
            {
                return offset;
            }

            set
            {
                offset = value;
                offsetSet = true;
                type = OperandType.Relative;
            }
        }
        public override string Text => offsetSet ? $"~{offset}" : Identifier;
    }

    class LocalOperand : Operand
    {
        public LocalOperand(ulong offset)
        {
            Offset = offset;
        }

        public override OperandType Type => OperandType.Local;
        public override string Text => $"LOCAL[{Offset}]";
        public ulong Offset { get; private set; }
    }

    class InstructionElement : PulsarAsmGrammarBaseListener, IAsmElement
    {
        public InstructionElement(PulsarAsmGrammarParser.InstructionContext ctx, Endianness endiannes, DataWidth standardDataSize, DataWidth standardAddressSize)
        {
            Endianness = endiannes;
            AddressWidth = standardAddressSize;
            DataWidth = standardDataSize;
            Text = ctx.GetText();
            Node = ctx;
        }

        public PulsarAsmGrammarParser.InstructionContext Node { get; }

        public string Text { get; private set; }

        public override void EnterInstr_body([NotNull] PulsarAsmGrammarParser.Instr_bodyContext context)
        {
            SetMnemonic(context);
        }
        private void SetMnemonic(PulsarAsmGrammarParser.Instr_bodyContext instrBodyNode)
        {
            string mnemo = instrBodyNode.MNEMONIC().GetText();
            Mnemonic = InstructionEncoding.ParseMnemonic(mnemo);
        }

        public override void EnterLabel([NotNull] PulsarAsmGrammarParser.LabelContext context)
        {
            SetLabel(context);
        }

        private void SetLabel(PulsarAsmGrammarParser.LabelContext ctx)
        {
            Label = ctx.IDENTIFIER()?.GetText();
        }

        private static (Immediate, OperandType) CreateImmediate(PulsarAsmGrammarParser.Op_immediateContext ctx)
        {
            if (ctx.OFFSET() != null)
            {
                return (new OffsetImmediate(ctx.IDENTIFIER().GetText()), OperandType.IdentifierOffset);
            }
            else
            {
                string integerText = ctx.GetText();

                return (new IntegerImmediate(InstructionEncoding.ParseInteger(integerText)), OperandType.Immediate);
            }
        }

        private static (Operand, OperandType) CreateJmpOperand(PulsarAsmGrammarParser.Jmp_operandContext ctx)
        {
            var jmpOp = ctx;
            if (jmpOp.op_base_w_offset() != null)
            {
                var op = jmpOp.op_base_w_offset();
                var (_, num) = InstructionEncoding.ParseRegister(op.GP_REGISTER().GetText());
                bool sign = op.SIGN().GetText() == "-";
                long offset = (long)InstructionEncoding.ParseInteger(op.unsigned_integer().GetText());
                offset = sign ? -offset : offset;
                return (new BaseWithImmediateOffset(num, offset), OperandType.BaseWithImmediateOffset);
            }
            else if (jmpOp.op_base_w_register() != null)
            {
                var op = jmpOp.op_base_w_register();
                var (_, num1) = InstructionEncoding.ParseRegister(op.GP_REGISTER(0).GetText());
                var (_, num2) = InstructionEncoding.ParseRegister(op.GP_REGISTER(1).GetText());
                return (new BaseWithRegisterOffset(num1, num2), OperandType.BaseWithRegisterOffset);
            }
            else if (jmpOp.op_data() != null)
            {
                var op = jmpOp.op_data();
                string id = op.IDENTIFIER().GetText();
                return (new DataOperand(id), OperandType.Identifier);
            }
            else if (jmpOp.op_imm_memory() != null)
            {
                var op = jmpOp.op_imm_memory();
                ulong addr = InstructionEncoding.ParseInteger(op.integer().GetText());
                return (new MemoryImmediate(addr), OperandType.MemoryImmediate);
            }
            else if (jmpOp.op_indirect() != null)
            {
                var op = jmpOp.op_indirect();
                var (_, num) = InstructionEncoding.ParseRegister(op.GP_REGISTER().GetText());
                return (new RegisterIndirectOperand(num), OperandType.Indirect);
            }
            else if (jmpOp.op_local() != null)
            {
                var op = jmpOp.op_local();
                ulong offset = InstructionEncoding.ParseInteger(op.integer().GetText());
                return (new LocalOperand(offset), OperandType.Local);
            }
            else if (jmpOp.op_relative() != null)
            {
                var op = jmpOp.op_relative();
                long offset = (long)InstructionEncoding.ParseInteger(op.integer().GetText());
                return (new ConcreteRelativeOperand(offset), OperandType.Relative);
            }
            else
            {
                throw new InvalidOperationException("Wrong operand");
            }
        }

        private static (Operand, OperandType) CreateStOperand(PulsarAsmGrammarParser.St_operandContext ctx)
        {
            if (ctx.op_register() != null)
            {
                var (kind, num) = InstructionEncoding.ParseRegister(ctx.op_register().GetText());
                return (new RegisterOperand(kind, num), OperandType.Register);
            }
            else if (ctx.jmp_operand() != null)
            {
                return CreateJmpOperand(ctx.jmp_operand());
            }
            else
            {
                throw new InvalidOperationException("Wrong operand");
            }
        }

        public override void EnterOperands([NotNull] PulsarAsmGrammarParser.OperandsContext context)
        {
            SetOperands(context);
        }

        private string OperandsNotSupportedMsg() => $"{Mnemonic} instruction doesn't support such operands";

        private void SetOperands(PulsarAsmGrammarParser.OperandsContext operands)
        {
            var st_operands = operands.st_operand();
            var op_immediate = operands.op_immediate();
            OperandType? first = null, second = null;
            if (st_operands.Length == 1 && op_immediate != null)
            {
                // Двухоперандная инструкция с непоср. операндом
                (Operand1, first) = CreateStOperand(st_operands[0]);
                (Operand2, second) = CreateImmediate(op_immediate);
            }
            else if (st_operands.Length == 2)
            {
                // Двухоперандная инструкция без непосредственного операнда
                (Operand1, first) = CreateStOperand(st_operands[0]);
                (Operand2, second) = CreateStOperand(st_operands[1]);
            }
            else if (st_operands.Length == 1)
            {
                // Однооперандная инструкция без непосредственного операнда
                (Operand1, first) = CreateStOperand(st_operands[0]);
            }
            else if (st_operands.Length == 0 && op_immediate != null)
            {
                // Однооперандная инструкция с непосредственным операндом
                (Operand1, first) = CreateImmediate(op_immediate);
            }
            else
            {
                // Безоперандная инструкция
            }
            SetOperandBytesAndOpcode();
        }

        public void ResetOperandBytes()
        {
            SetOperandBytesAndOpcode();
            SetConditionalJumpBytes();
            SetConditionalSetBytes();
        }

        public void ResolveIdentifiers(ElementIds ids, uint myOffset)
        {
            static void ResolveId(Operand op, IParseTree node, ElementIds ids, uint myOffset)
            {
                switch (op.Type)
                {
                    case OperandType.Identifier:
                        DataOperand data = (DataOperand)op;
                        try
                        {
                            var otherProps = ids.idToNode[data.Identifier];
                            /*if (otherProps.type == ElementType.Instruction)
                            {
                                throw new InvalidOperationException("Label as data reference is not allowed");
                            }
                            else if (otherProps.type == ElementType.Procedure)
                            {
                                throw new InvalidOperationException("Procedure as data reference is not allowed");
                            }*/
                            uint otherOffset = ids.nodeToId[otherProps.node].offset;
                            int resultOffset = (int)otherOffset - (int)myOffset;
                            data.Offset = resultOffset;
                        }
                        catch (Exception)
                        {
                            throw new InvalidOperationException("Cannot resolve identifier \"" + data.Identifier + "\"");
                        }
                        break;
                    case OperandType.IdentifierOffset:
                        OffsetImmediate off = (OffsetImmediate)op;
                        try
                        {
                            var otherProps = ids.idToNode[off.OperandId];
                            var otherOffset = ids.nodeToId[otherProps.node].offset;
                            off.SetValue(otherOffset);
                        }
                        catch (Exception)
                        {
                            throw new InvalidOperationException("Cannot resolve identifier " + off.OperandId + "\"");
                        }
                        break;
                }
            }

            if (Operand1 != null)
            {
                ResolveId(Operand1, Node, ids, myOffset);
            }
            if (Operand2 != null)
            {
                ResolveId(Operand2, Node, ids, myOffset);
            }
            if (JmpTrue != null)
            {
                ResolveId(JmpTrue, Node, ids, myOffset);
            }
            if (JmpFalse != null)
            {
                ResolveId(JmpFalse, Node, ids, myOffset);
            }
            if (ConditionalSetOperand != null)
            {
                ResolveId(ConditionalSetOperand, Node, ids, myOffset);
            }
            ResetOperandBytes();
        }

        private void SetOperandBytesAndOpcode()
        {
            InstructionClass actualClass;
            OperandType? first = Operand1?.Type;
            OperandType? second = Operand2?.Type;
            (PlanePrefix, AdditionalAddrMode, actualClass) = InstructionEncoding.GetPlanePrefixes(Mnemonic, first, second);
            OperandType[] types;
            if (first != null && second != null)
            {
                types = new OperandType[] { first.Value, second.Value };
            }
            else if (first != null && second == null)
            {
                types = new OperandType[] { first.Value };
            }
            else if (first == null)
            {
                types = Array.Empty<OperandType>();
            }
            else
            {
                throw new InvalidOperationException();
            }
            if (!InstructionEncoding.OperandsOk(Mnemonic, types))
            {
                throw new InvalidOperationException(OperandsNotSupportedMsg());
            }
            switch (actualClass)
            {
                case InstructionClass.Op1:
                case InstructionClass.Op1Imm:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    break;
                case InstructionClass.Op2:
                case InstructionClass.Op2Imm:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    OpData2 = InstructionEncoding.GetOperandBits(Operand2, DataWidth, AddressWidth, Endianness);
                    break;
                default:
                    // Остальные классы обработаются здесь
                    SetSpecialOperandBytes();
                    break;
            }
            InstrPlane instrPlane = actualClass switch
            {
                InstructionClass.Basic => InstrPlane.Basic,
                InstructionClass.Priv => InstrPlane.Priv,
                InstructionClass.Op1 => InstrPlane.Op1,
                InstructionClass.Op1Imm => InstrPlane.Op1Imm,
                InstructionClass.Op2 => InstrPlane.Op2,
                InstructionClass.Op2Imm => InstrPlane.Op2Imm,
                _ => throw new InvalidOperationException("Plane not supported: " + actualClass),
            };
            Opcode = InstructionEncoding.GetOpcode(instrPlane, Mnemonic);
            RecalculateTotalBytesCount();
        }

        /*public override void EnterInstr_specifier_sequence([NotNull] PulsarAsmGrammarParser.Instr_specifier_sequenceContext context)
        {
            SetSpecifiers(context);
        }

        private void SetSpecifiers(PulsarAsmGrammarParser.Instr_specifier_sequenceContext ctx)
        {
            while (ctx != null)
            {
                var specifierNode = ctx.instruction_specifier();
                SetSpecifier(specifierNode);
            }
        }*/

        public override void EnterConditional_body_shared([NotNull] PulsarAsmGrammarParser.Conditional_body_sharedContext context)
        {
            SetConditionalShared(context);
        }

        private void SetConditionalShared(PulsarAsmGrammarParser.Conditional_body_sharedContext ctx)
        {
            Condition = InstructionEncoding.ParseCondition(ctx.CONDITION().GetText());
            Cond = InstructionEncoding.GetCondition(Condition.Value);
        }

        public override void EnterJump_sequence([NotNull] PulsarAsmGrammarParser.Jump_sequenceContext context)
        {
            SetConditionalJump(context);
        }

        private void SetConditionalJumpBytes()
        {
            if (Jmpcond != null)
            {
                JmpTrueOrSetBytes = InstructionEncoding.GetOperandBits(JmpTrue, DataWidth, AddressWidth, Endianness);
            }
            if (Jmpcond2 != null)
            {
                JmpFalseBytes = InstructionEncoding.GetOperandBits(JmpFalse, DataWidth, AddressWidth, Endianness);
            }
            RecalculateTotalBytesCount();
        }

        private void SetConditionalJump(PulsarAsmGrammarParser.Jump_sequenceContext ctx)
        {
            var jmpOps = ctx.jmp_operand();
            OperandType trueType;
            OperandType? falseType = null;
            if (jmpOps.Length == 2)
            {
                (JmpFalse, falseType) = CreateJmpOperand(jmpOps[1]);
            }
            (JmpTrue, trueType) = CreateJmpOperand(jmpOps[0]);
            (Jmpcond, Jmpcond2) = InstructionEncoding.GetConditionalJmpPrefixes(trueType, falseType);
            SetConditionalJumpBytes();
        }

        public override void EnterConditional_cp_instruction([NotNull] PulsarAsmGrammarParser.Conditional_cp_instructionContext context)
        {
            SetConditionalSet(context);
        }

        public void SetConditionalSetBytes()
        {
            if (ConditionalSetOperand != null)
            {
                JmpTrueOrSetBytes = InstructionEncoding.GetOperandBits(ConditionalSetOperand, DataWidth, AddressWidth, Endianness);
                RecalculateTotalBytesCount();
            }
        }

        private void SetConditionalSet(PulsarAsmGrammarParser.Conditional_cp_instructionContext ctx)
        {
            var op = ctx.st_operand();
            OperandType type;
            (ConditionalSetOperand, type) = CreateStOperand(op);
            Condflgst = InstructionEncoding.GetConditionalSetPrefix(type);
            SetConditionalSetBytes();
        }

        private void SetSpecialOperandBytes()
        {
            switch (Mnemonic)
            {
                case MnemonicType.Int:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth.I8, AddressWidth, Endianness);
                    break;
                case MnemonicType.Restreg:
                case MnemonicType.Strreg:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    if (OpData1[0] >= 18)
                    {
                        throw new InvalidOperationException("RESTREG and STRREG immediate must be between 0 and 18");
                    }
                    break;
                case MnemonicType.Cpysx:
                case MnemonicType.Cpyzx:
                    bool signExtended = Mnemonic == MnemonicType.Cpysx;
                    (Opcode, AdditionalAddrMode) = InstructionEncoding.GetCpyxOpcodeAndField(signExtended, DataWidth, DataWidth2, Operand1.Type, Operand2.Type);
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    OpData2 = InstructionEncoding.GetOperandBits(Operand2, DataWidth2, AddressWidth, Endianness);
                    break;
                case MnemonicType.Allocvars:
                    OpData1 = new byte[2];
                    (OpData1[0], OpData1[1]) = InstructionEncoding.GetAllocvarsImmediate(Operand1, Endianness);
                    break;
                case MnemonicType.Getretptr:
                case MnemonicType.Setretptr:
                case MnemonicType.Loadctx:
                case MnemonicType.Savectx:
                    OpData1 = new byte[1];
                    OpData1[0] = InstructionEncoding.GetRegisterByte(Operand1);
                    break;
                case MnemonicType.Getcdptr:
                    OpData1 = new byte[1];
                    OpData1[0] = InstructionEncoding.GetRegisterByte(Operand1, Operand2);
                    break;
                case MnemonicType.Callnat:
                case MnemonicType.Jmpnat:
                case MnemonicType.Jmpusr:
                    if (!AddressSizeExplicit)
                    {
                        throw new InvalidOperationException("CALLNAT address size must be set explicitly");
                    }
                    AdditionalAddrMode = InstructionEncoding.GetOperandModeBits(Operand1.Type, null);
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    break;
                case MnemonicType.Rdinforeg:
                case MnemonicType.Rdsysreg:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    OpData2 = InstructionEncoding.GetOperandBits(Operand2, DataWidth, AddressWidth, Endianness);
                    break;
                case MnemonicType.Wrsysreg:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand2, DataWidth, AddressWidth, Endianness);
                    OpData2 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    break;
                case MnemonicType.Rdport:
                case MnemonicType.Wrport:
                    OpData1 = InstructionEncoding.GetOperandBits(Operand1, DataWidth, AddressWidth, Endianness);
                    var data2 = InstructionEncoding.GetOperandBits(Operand2, DataWidth, AddressWidth, Endianness);
                    OpData1[0] |= (byte)(data2[0] >> 4);
                    break;
                default:
                    // Все остальные команды
                    break;
            }
        }

        public override void EnterInstruction_specifier([NotNull] PulsarAsmGrammarParser.Instruction_specifierContext context)
        {
            SetSpecifier(context);
        }

        private void SetSpecifier(PulsarAsmGrammarParser.Instruction_specifierContext ctx)
        {
            if (ctx.UNALIGNED() != null)
            {
                if (UnalignedPrefix != null)
                {
                    throw new InvalidOperationException("More than one .UNALIGNED specifier is not alowed");
                }
                UnalignedPrefix = InstructionEncoding.UnalignedPrefix;
            }
            else if (ctx.ADDRESS_TYPE_SPECIFIER() != null)
            {
                if (!AddressSizeExplicit)
                {
                    string addressSpecifierText = ctx.ADDRESS_TYPE_SPECIFIER().GetText();
                    var addrWidth = InstructionEncoding.GetDataAddressWidth(addressSpecifierText);
                    AddressWidth = addrWidth;
                    if (Mnemonic != MnemonicType.Chngmode)
                    {
                        (SzPrefix, SzSupPrefix) = InstructionEncoding.GetDataTypePrefixes(DataWidth, addrWidth);
                    }
                    else
                    {
                        OpData1 = new byte[] { InstructionEncoding.GetChngmodeImmediate(DataWidth, AddressWidth) };
                    }
                }
                else
                {
                    throw new InvalidOperationException("More than one address size specifier is not allowed");
                }
            }
            else if (ctx.DATA_TYPE_SPECIFIER() != null)
            {
                if (!DataSizeExplicit)
                {
                    string dataSpecifierText = ctx.DATA_TYPE_SPECIFIER().GetText();
                    var dataWidth = InstructionEncoding.GetDataAddressWidth(dataSpecifierText);
                    DataWidth = dataWidth;
                    if (Mnemonic != MnemonicType.Cpysx && Mnemonic != MnemonicType.Cpyzx && Mnemonic != MnemonicType.Chngmode)
                    {
                        (SzPrefix, SzSupPrefix) = InstructionEncoding.GetDataTypePrefixes(dataWidth, AddressWidth);
                    }
                    else if (Mnemonic == MnemonicType.Chngmode)
                    {
                        OpData1 = new byte[] { InstructionEncoding.GetChngmodeImmediate(DataWidth, AddressWidth) };
                    }
                    DataSizeExplicit = true;
                }
                else
                {
                    if (Mnemonic != MnemonicType.Cpysx && Mnemonic != MnemonicType.Cpyzx)
                    {
                        throw new InvalidOperationException("More than one data size specifier is not allowed (except CPYZX/CPYSX)");
                    }
                    string dataSpecifierText = ctx.DATA_TYPE_SPECIFIER().GetText();
                    var dataWidth = InstructionEncoding.GetDataAddressWidth(dataSpecifierText);
                    DataWidth2 = dataWidth;
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public IEnumerator<IReadOnlyList<byte>> GetEnumerator()
        {
            static byte[] AsArr(byte val)
            {
                return new byte[] { val };
            }

            if (UnalignedPrefix != null)
            {
                yield return AsArr(UnalignedPrefix.Value);
            }
            if (SzPrefix != null)
            {
                yield return AsArr(SzPrefix.Value);
            }
            if (SzSupPrefix != null)
            {
                yield return AsArr(SzSupPrefix.Value);
            }
            if (Condflgst != null)
            {
                yield return AsArr(Condflgst.Value);
            }
            else if (Jmpcond != null)
            {
                yield return AsArr(Jmpcond.Value);
            }
            if (Jmpcond2 != null)
            {
                yield return AsArr(Jmpcond.Value);
            }
            if (PlanePrefix != null)
            {
                yield return AsArr(PlanePrefix.Value);
            }
            yield return AsArr(Opcode);
            if (AdditionalAddrMode != null)
            {
                yield return AsArr(AdditionalAddrMode.Value);
            }
            if (OpData1 != null)
            {
                yield return OpData1;
            }
            if (OpData2 != null)
            {
                yield return OpData2;
            }
            if (Cond != null)
            {
                yield return AsArr(Cond.Value);
            }
            if (JmpTrueOrSetBytes != null)
            {
                yield return JmpTrueOrSetBytes;
            }
            if (JmpFalseBytes != null)
            {
                yield return JmpFalseBytes;
            }
        }

        public Endianness Endianness { get; }
        public string Label { get; private set; }
        public MnemonicType Mnemonic { get; private set; }
        public DataWidth DataWidth { get; private set; }
        public DataWidth DataWidth2 { get; private set; }
        public DataWidth AddressWidth { get; private set; }
        public byte? UnalignedPrefix { get; private set; }
        public byte? PlanePrefix { get; private set; }
        public byte? SzPrefix { get; private set; }
        public bool AddressSizeExplicit { get; private set; }
        public bool DataSizeExplicit { get; private set; }
        public byte? SzSupPrefix { get; private set; }
        public byte Opcode { get; private set; }
        public byte? AdditionalAddrMode { get; private set; }
        public byte[] OpData1 { get; private set; }
        public byte[] OpData2 { get; private set; }
        public InstructionConditionTokenType? Condition { get; private set; }
        public byte? Cond { get; private set; }
        public byte? Condflgst { get; private set; }
        public byte? Jmpcond { get; private set; }
        public byte? Jmpcond2 { get; private set; }
        public byte[] JmpTrueOrSetBytes { get; private set; }
        public byte[] JmpFalseBytes { get; private set; }
        // Байты операндов "особенных" инструкций
        public Operand Operand1 { get; private set; }
        public Operand Operand2 { get; private set; }
        public bool? ConditionalJmp { get; private set; } // Условный переход или условная запись?
        public Operand JmpTrue { get; private set; }
        public Operand JmpFalse { get; private set; }
        public Operand ConditionalSetOperand { get; private set; }
        public IList<InstructionTypeSpecifier> Specifiers { get; } = new List<InstructionTypeSpecifier>();
        public int TotalBytesCount { get; private set; } = 0;

        public int Count => 0;

        public IAsmElement this[int index] => throw new InvalidOperationException();

        public void RecalculateTotalBytesCount()
        {
            TotalBytesCount = 1; // Как минимум опкод
            if (UnalignedPrefix != null)
            {
                TotalBytesCount++;
            }
            if (SzPrefix != null)
            {
                TotalBytesCount++;
            }
            if (SzSupPrefix != null)
            {
                TotalBytesCount++;
            }
            if (PlanePrefix != null)
            {
                TotalBytesCount++;
            }
            if (AdditionalAddrMode != null)
            {
                TotalBytesCount++;
            }
            if (OpData1 != null)
            {
                TotalBytesCount += OpData1.Length;
            }
            if (OpData2 != null)
            {
                TotalBytesCount += OpData2.Length;
            }
            if (Condflgst != null)
            {
                TotalBytesCount += 2; //CONDFLGST, COND
            }
            else if (Jmpcond != null)
            {
                TotalBytesCount++;
            }
            if (Jmpcond2 != null)
            {
                TotalBytesCount++;
            }
            if (Cond != null)
            {
                TotalBytesCount++;
            }
            if (JmpTrueOrSetBytes != null)
            {
                TotalBytesCount += JmpTrueOrSetBytes.Length;
            }
            if (JmpFalseBytes != null)
            {
                TotalBytesCount += JmpFalseBytes.Length;
            }
        }

        IEnumerator<IAsmElement> IEnumerable<IAsmElement>.GetEnumerator()
        {
            yield break;
        }
    }

    class Procedure : PulsarAsmGrammarBaseListener, IAsmElement
    {
        public Procedure(PulsarAsmGrammarParser.ProcedureContext ctx, uint startingOffset, Endianness endianness, DataWidth stDataSize, DataWidth stAddrWidth)
        {
            Name = ctx.proc_header().IDENTIFIER().GetText();
            Text = ctx.GetText();
            Endianness = endianness;
            DataSize = stDataSize;
            AddressSize = stAddrWidth;
            ids = new ElementIds
            {
                idToNode = new Dictionary<string, IdentifierProps>(),
                nodeToId = new Dictionary<IParseTree, (string, uint offset, IdentifierProps)>(),
            };
            currentOffset = startingOffset;
            Node = ctx;
        }

        public PulsarAsmGrammarParser.ProcedureContext Node { get; }

        ElementIds ids;
        uint currentOffset;

        public Endianness Endianness { get; }
        public DataWidth DataSize { get; }
        public DataWidth AddressSize { get; }

        public override void EnterData_definition_statement([NotNull] PulsarAsmGrammarParser.Data_definition_statementContext context)
        {
            DataElement data = new DataElement(context, Endianness);
            // Заполняем данные
            ParseTreeWalker.Default.Walk(data, context);
            Elements.Add(data);
            if (data.Id != null)
            {
                ids.idToNode.Add(data.Id, new IdentifierProps(context, ElementType.DataDefinitionStatement));
            }
            ids.nodeToId.Add(context, (data.Id, currentOffset, new IdentifierProps(context, ElementType.DataDefinitionStatement)));
            currentOffset += (uint)data.TotalBytesCount;
            TotalBytesCount += data.TotalBytesCount;
        }

        public override void EnterInstruction([NotNull] PulsarAsmGrammarParser.InstructionContext context)
        {
            InstructionElement instr = new InstructionElement(context, Endianness, DataSize, AddressSize);
            ParseTreeWalker.Default.Walk(instr, context);
            Elements.Add(instr);
            if (instr.Label != null)
            {
                ids.idToNode.Add(instr.Label, new IdentifierProps(context, ElementType.Instruction));
            }
            ids.nodeToId.Add(context, (instr.Label, currentOffset, new IdentifierProps(context, ElementType.Instruction)));
            currentOffset += (uint)instr.TotalBytesCount;
            TotalBytesCount += instr.TotalBytesCount;
        }

        public void ResolveIdentifiers(ElementIds outterIds)
        {
            // Второй проход
            foreach (IAsmElement elem in Elements)
            {
                if (elem is InstructionElement i)
                {
                    var itsOffset = ids.nodeToId[i.Node].offset;
                    try
                    {
                        i.ResolveIdentifiers(ids, itsOffset);
                    }
                    catch (Exception e)
                    {
                        try
                        {
                            i.ResolveIdentifiers(outterIds, itsOffset);
                        }
                        catch (Exception e1)
                        {
                            throw new InvalidOperationException("Cannot resolve identifier: maybe it is in other scope", e1);
                        }
                    }
                }
            }
        }

        public string Text { get; private set; }

        public string Name { get; private set; }

        public int TotalBytesCount { get; private set; } = 0;

        public IEnumerator<IReadOnlyList<byte>> GetEnumerator()
        {
            foreach (IAsmElement elem in Elements)
            {
                foreach (IReadOnlyList<byte> sublist in (IEnumerable<IReadOnlyList<byte>>)elem)
                {
                    yield return sublist;
                }
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        IEnumerator<IAsmElement> IEnumerable<IAsmElement>.GetEnumerator()
        {
            foreach (IAsmElement e in Elements)
            {
                yield return e;
            }
        }

        private IList<IAsmElement> Elements { get; } = new List<IAsmElement>();

        public int Count => Elements.Count;

        public IAsmElement this[int index] => Elements[index];
    }
}
