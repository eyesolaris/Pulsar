using Antlr4.Runtime;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace PulsarAssembler
{
    [Flags]
    public enum InstructionClass
    {
        Basic = 1,
        Priv = 2,
        Op0 = 4,
        Op1 = 8,
        Op1Imm = 16,
        Op2 = 32,
        Op2Imm = 64,
        Op2Any = Op2 | Op2Imm,
        All = Basic | Priv | Op0 | Op1 | Op1Imm | Op2 | Op2Imm,
    }

    static class InstructionEncoding
    {
        public static bool OperandsOk(MnemonicType mnemonic, params OperandType[] opTypes)
        {
            static bool InstructionTypeFlagsOk(InstructionClass instrPlanes, InstructionClass classToCheck)
            {
                if (!instrPlanes.HasFlag(classToCheck))
                {
                    return false;
                }
                return true;
            }

            InstructionClass instrPlanes = GetInstructionClasses(mnemonic);

            if (mnemonic == MnemonicType.Invalid || mnemonic == MnemonicType.Nop)
            {
                // Инструкции INVALID и NOP могут адресовать всё, что угодно, кроме системных и информационных регистров
                if (opTypes.Length == 1 && (opTypes[0] == OperandType.SystemRegister || opTypes[0] == OperandType.InfoRegister))
                {
                    return false;
                }
                return true;
            }

            if (instrPlanes == InstructionClass.Basic)
            {
                if (opTypes.Length == 2)
                {
                    switch (mnemonic)
                    {
                        case MnemonicType.Getcdptr:
                            if (opTypes[0] == opTypes[1] &&
                                opTypes[0] == OperandType.Register)
                            {
                                return true;
                            }
                            return false;
                        case MnemonicType.Cpysx:
                        case MnemonicType.Cpyzx:
                            return true;
                        default:
                            return false;
                    }
                }
                else if (opTypes.Length == 1)
                {
                    switch (mnemonic)
                    {
                        case MnemonicType.Int:
                        case MnemonicType.Allocvars:
                            if (opTypes[0] == OperandType.Immediate)
                            {
                                return true;
                            }
                            return false;
                        case MnemonicType.Getretptr:
                        case MnemonicType.Setretptr:
                        case MnemonicType.Loadctx:
                        case MnemonicType.Savectx:
                            if (opTypes[0] == OperandType.Register)
                            {
                                return true;
                            }
                            return false;
                        default:
                            return false;
                    }
                }
                else if (opTypes.Length == 0)
                {
                    switch (mnemonic)
                    {
                        case MnemonicType.Ret:
                        case MnemonicType.Syscall:
                        case MnemonicType.Chngmode:
                        case MnemonicType.Smcodst:
                        case MnemonicType.Smcodend:
                        case MnemonicType.Sysid:
                        case MnemonicType.Dbgint:
                        case MnemonicType.Clrst:
                            return true;
                        default:
                            return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else if (instrPlanes == InstructionClass.Priv)
            {
                if (opTypes.Length == 2)
                {
                    switch (mnemonic)
                    {
                        case MnemonicType.Rdinforeg:
                            if (opTypes[0] == OperandType.Register &&
                                opTypes[1] == OperandType.InfoRegister)
                            {
                                return true;
                            }
                            return false;
                        case MnemonicType.Rdsysreg:
                            if (opTypes[0] == OperandType.Register &&
                                opTypes[1] == OperandType.SystemRegister)
                            {
                                return true;
                            }
                            return false;
                        case MnemonicType.Wrsysreg:
                            if (opTypes[0] == OperandType.SystemRegister &&
                                opTypes[1] == OperandType.Register)
                            {
                                return true;
                            }
                            return false;
                        case MnemonicType.Rdport:
                        case MnemonicType.Wrport:
                            if (opTypes[0] == opTypes[1] &&
                                opTypes[0] == OperandType.Register)
                            {
                                return true;
                            }
                            return false;
                        default:
                            return false;
                    }
                }
                if (opTypes.Length == 1)
                {
                    var t = opTypes[0];
                    switch (mnemonic)
                    {
                        case MnemonicType.Callnat:
                        case MnemonicType.Jmpnat:
                        case MnemonicType.Jmpusr:
                            if (t == OperandType.Immediate ||
                                t == OperandType.IdentifierOffset ||
                                t == OperandType.Register ||
                                t == OperandType.SystemRegister ||
                                t == OperandType.InfoRegister)
                            {
                                return false;
                            }
                            return true;
                        case MnemonicType.Prrdstatreg:
                            if (t == OperandType.Register)
                            {
                                return true;
                            }
                            return false;
                        case MnemonicType.Restreg:
                        case MnemonicType.Strreg:
                            if (t == OperandType.Immediate)
                            {
                                return true;
                            }
                            return false;
                        default:
                            return false;
                    }
                }
                else if (opTypes.Length == 0)
                {
                    switch (mnemonic)
                    {
                        case MnemonicType.Fwcall:
                        case MnemonicType.Fbdint:
                        case MnemonicType.Alwint:
                        case MnemonicType.Getintflag:
                        case MnemonicType.Iret:
                            return true;
                        default:
                            return false;
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                if (opTypes.Length == 2)
                {
                    if (opTypes[1] == OperandType.Immediate || opTypes[1] == OperandType.IdentifierOffset)
                    {
                        return InstructionTypeFlagsOk(instrPlanes, InstructionClass.Op2Imm);

                    }
                    else
                    {
                        return InstructionTypeFlagsOk(instrPlanes, InstructionClass.Op2);
                    }
                }
                else if (opTypes.Length == 1)
                {
                    if (opTypes[0] == OperandType.Immediate || opTypes[0] == OperandType.IdentifierOffset)
                    {
                        return InstructionTypeFlagsOk(instrPlanes, InstructionClass.Op1Imm);
                    }
                    else
                    {
                        return InstructionTypeFlagsOk(instrPlanes, InstructionClass.Op1);
                    }
                }
                else
                {
                    return false;
                }
            }
        }

        public static InstructionClass GetInstructionClasses(MnemonicType mnemonic)
        {
            switch (mnemonic)
            {
                case MnemonicType.Invalid:
                case MnemonicType.Nop:
                    return InstructionClass.All;
                case MnemonicType.Ret:
                case MnemonicType.Int:
                case MnemonicType.Syscall:
                case MnemonicType.Chngmode:
                case MnemonicType.Smcodst:
                case MnemonicType.Smcodend:
                case MnemonicType.Sysid:
                case MnemonicType.Allocvars:
                case MnemonicType.Dbgint:
                case MnemonicType.Getretptr:
                case MnemonicType.Setretptr:
                case MnemonicType.Clrst:
                case MnemonicType.Getcdptr:
                case MnemonicType.Cpyzx:
                case MnemonicType.Cpysx:
                case MnemonicType.Loadctx:
                case MnemonicType.Savectx:
                    return InstructionClass.Basic;
                case MnemonicType.Callnat:
                case MnemonicType.Jmpnat:
                case MnemonicType.Rdinforeg:
                case MnemonicType.Fwcall:
                case MnemonicType.Jmpusr:
                case MnemonicType.Rdsysreg:
                case MnemonicType.Wrsysreg:
                case MnemonicType.Rdport:
                case MnemonicType.Wrport:
                case MnemonicType.Prrdstatreg:
                case MnemonicType.Fbdint:
                case MnemonicType.Alwint:
                case MnemonicType.Getintflag:
                case MnemonicType.Iret:
                case MnemonicType.Restreg:
                case MnemonicType.Strreg:
                    return InstructionClass.Priv;
                case MnemonicType.Call:
                case MnemonicType.Zero:
                case MnemonicType.Fill:
                case MnemonicType.Not:
                case MnemonicType.Neg:
                case MnemonicType.Shr:
                case MnemonicType.Shl:
                case MnemonicType.Sar:
                case MnemonicType.Rtr:
                case MnemonicType.Rtl:
                case MnemonicType.Incr:
                case MnemonicType.Decr:
                case MnemonicType.Pop:
                case MnemonicType.Alignleft:
                case MnemonicType.Alignright:
                case MnemonicType.Getfromd:
                case MnemonicType.Setfromd:
                case MnemonicType.Rdtcks:
                case MnemonicType.Getip:
                case MnemonicType.Getstreg:
                case MnemonicType.Jmp:
                case MnemonicType.Getctxsz:
                case MnemonicType.Getcaptr:
                case MnemonicType.Ftrunc:
                case MnemonicType.Ftontte:
                case MnemonicType.Ftontafz:
                case MnemonicType.Frotopinf:
                case MnemonicType.Frotominf:
                case MnemonicType.Rdstatreg:
                    return InstructionClass.Op1;
                case MnemonicType.Push:
                case MnemonicType.Setstreg:
                    return InstructionClass.Op1 | InstructionClass.Op1Imm;
                default:
                    // Остальные для краткости
                    return InstructionClass.Op2Any;
            }
        }

        private const byte OP1IMM = 0xFE;
        private const byte OP1 = 0xC0;
        private const byte OP2 = 0x80;
        private const byte OP2IMM = 0xC8;
        private const byte SZ = 0xD0;
        // на самом деле, это не значение префикса SZSUP, но так удобнее устанавливать биты
        private const byte SZSUP = 0xF8;
        private const byte UNALIGNED = 0x68;

        private const byte CPYZX = 0b00010000;
        private const byte CPYSZ = 0b00011000;
        private const byte CPYX_NARROW = 0b010000;

        private const byte JMPCOND = 0x70;
        private const byte CONDFLGST = 0x60;

        private const byte GP_REGISTER = 0b000;
        private const byte MEM_IMM = 0b001;
        private const byte INDIRECT = 0b010;
        private const byte LOCAL = 0b011;
        private const byte BASE_IMM = 0b100;
        private const byte BASE_REG = 0b101;
        private const byte RELATIVE = 0b110;

        public static byte UnalignedPrefix { get => UNALIGNED; }

        public static byte GetChngmodeImmediate(DataWidth data, DataWidth addresses)
        {
            byte imm = 0;
            imm |= (byte)(GetDataWidthBits(data) | (GetAddressWidthBits(addresses) << 2));
            return imm;
        }

        public static (byte, byte) GetAllocvarsImmediate(Operand operand, Endianness endianness)
        {
            ulong allocImm = ((Immediate)operand).UnsignedVal;
            if (allocImm > ushort.MaxValue)
            {
                throw new InvalidOperationException("ALLOCVARS immediate out of range");
            }
            byte[] data = AdjustEndianness((ushort)allocImm, endianness);
            return (data[0], data[1]);
        }

        public static byte GetGetcdptrImmediate(Operand firstOp, Operand secondOp)
        {
            return GetRegisterByte(
                ((RegisterOperand)firstOp).RegisterInfo.Item2,
                ((RegisterOperand)secondOp).RegisterInfo.Item2);
        }

        public static byte GetRegisterByte(byte firstNum, byte? secondNum = null)
        {
            if (firstNum > 0x0F)
            {
                throw new InvalidOperationException("First register number out of range");
            }
            byte regs = 0;
            regs |= (byte)(firstNum << 4);
            if (secondNum != null)
            {
                if (secondNum.Value >= 0x0F)
                {
                    throw new InvalidOperationException("Second register number out of range");
                }
                regs |= secondNum.Value;
            }
            return regs;
        }

        public static byte GetRegisterByte(Operand operand1, Operand operand2 = null)
        {
            byte firstRegister = ((RegisterOperand)operand1).RegisterInfo.Item2;
            byte? secondRegister = null;
            if (operand2 != null)
            {
                secondRegister = ((RegisterOperand)operand2).RegisterInfo.Item2;
            }
            return GetRegisterByte(
                firstRegister, secondRegister);
        }

        public static byte GetOperandModeBits(OperandType first, OperandType? second)
        {
            byte bits = 0;

            static byte lowerBits(OperandType type)
            {
                switch (type)
                {
                    case OperandType.BaseWithImmediateOffset:
                        return BASE_IMM;
                    case OperandType.BaseWithRegisterOffset:
                        return BASE_REG;
                    case OperandType.Identifier:
                    case OperandType.Relative:
                        return RELATIVE;
                    case OperandType.Indirect:
                        return INDIRECT;
                    case OperandType.Local:
                        return LOCAL;
                    case OperandType.MemoryImmediate:
                        return MEM_IMM;
                    case OperandType.Register:
                        return GP_REGISTER;
                }
                return 0;
            }

            if (second != null)
            {
                bits |= (byte)(lowerBits(second.Value) << 3);
            }
            bits |= lowerBits(first);
            return bits;
        }

        public static byte[] GetOperandBits(Operand op, DataWidth dataWidth, DataWidth addressWidth, Endianness endianness)
        {
            static Exception Ex(DataWidth width)
            {
                throw new InvalidOperationException($"Wrong data/address width: " + width);
            }

            static bool ImmediateOk(DataWidth width, ulong imm)
            {
                return width switch
                {
                    DataWidth.I8 => imm <= byte.MaxValue,
                    DataWidth.I16 => imm <= ushort.MaxValue,
                    DataWidth.I32 => imm <= uint.MaxValue,
                    _ => true,
                };
            }

            List<byte> immData;

            static bool ImmediateSignedOk(DataWidth width, long imm)
            {
                return width switch
                {
                    DataWidth.I8 => imm <= sbyte.MaxValue && imm >= sbyte.MinValue,
                    DataWidth.I16 => imm <= short.MaxValue && imm >= short.MinValue,
                    DataWidth.I32 => imm <= int.MaxValue && imm >= int.MinValue,
                    _ => true,
                };
            }

            switch (op.Type)
            {
                case OperandType.BaseWithImmediateOffset:
                    BaseWithImmediateOffset bwi = (BaseWithImmediateOffset)op;
                    if (!ImmediateSignedOk(dataWidth, bwi.Offset))
                    {
                        throw Ex(dataWidth);
                    }
                    var reg = GetRegisterByte(bwi.RegisterInfo.Item2);
                    long data = bwi.Offset;
                    immData = dataWidth switch
                    {
                        DataWidth.I8 => new List<byte>() { reg, (byte)data },
                        DataWidth.I16 => new List<byte>(AdjustEndianness((ushort)data, endianness)),
                        DataWidth.I32 => new List<byte>(AdjustEndianness((uint)data, endianness)),
                        DataWidth.I64 => new List<byte>(AdjustEndianness((ulong)data, endianness)),
                        _ => throw Ex(dataWidth),
                    };
                    break;
                case OperandType.BaseWithRegisterOffset:
                    BaseWithRegisterOffset bwr = (BaseWithRegisterOffset)op;
                    reg = GetRegisterByte(bwr.RegisterInfo.Item2, bwr.SecondRegNumber);
                    immData = new List<byte>() { reg };
                    break;
                case OperandType.Identifier:
                case OperandType.Relative:
                    RelativeOperand rel = (RelativeOperand)op;
                    if (!ImmediateSignedOk(addressWidth, rel.Offset))
                    {
                        throw Ex(addressWidth);
                    }
                    immData = addressWidth switch
                    {
                        DataWidth.I8 => new List<byte>() { (byte)rel.Offset },
                        DataWidth.I16 => new List<byte>(AdjustEndianness((ushort)rel.Offset, endianness)),
                        DataWidth.I32 => new List<byte>(AdjustEndianness((uint)rel.Offset, endianness)),
                        DataWidth.I64 => new List<byte>(AdjustEndianness((ulong)rel.Offset, endianness)),
                        _ => throw Ex(addressWidth),
                    };
                    break;
                case OperandType.IdentifierOffset:
                case OperandType.Immediate:
                    Immediate immOp = (Immediate)op;
                    if (!ImmediateOk(dataWidth, immOp.UnsignedVal))
                    {
                        throw Ex(dataWidth);
                    }
                    immData = dataWidth switch
                    {
                        DataWidth.I8 => new List<byte>() { (byte)immOp.UnsignedVal },
                        DataWidth.I16 => new List<byte>(AdjustEndianness((ushort)immOp.UnsignedVal, endianness)),
                        DataWidth.I32 => new List<byte>(AdjustEndianness((uint)immOp.UnsignedVal, endianness)),
                        DataWidth.I64 => new List<byte>(AdjustEndianness(immOp.UnsignedVal, endianness)),
                        _ => throw Ex(dataWidth),
                    };
                    break;
                case OperandType.Indirect:
                case OperandType.Register:
                    RegisterOperand regOp = (RegisterOperand)op;
                    reg = GetRegisterByte(regOp.RegisterInfo.Item2);
                    immData = new List<byte>() { reg };
                    break;
                case OperandType.InfoRegister:
                case OperandType.SystemRegister:
                    regOp = (RegisterOperand)op;
                    reg = regOp.RegisterInfo.Item2;
                    immData = new List<byte>() { reg };
                    break;
                case OperandType.Local:
                    LocalOperand loc = (LocalOperand)op;
                    if (!ImmediateOk(addressWidth, loc.Offset))
                    {
                        throw Ex(addressWidth);
                    }
                    immData = addressWidth switch
                    {
                        DataWidth.I8 => new List<byte>() { (byte)loc.Offset },
                        DataWidth.I16 => new List<byte>(AdjustEndianness((ushort)loc.Offset, endianness)),
                        DataWidth.I32 => new List<byte>(AdjustEndianness((uint)loc.Offset, endianness)),
                        DataWidth.I64 => new List<byte>(AdjustEndianness(loc.Offset, endianness)),
                        _ => throw Ex(addressWidth),
                    };
                    break;
                case OperandType.MemoryImmediate:
                    MemoryImmediate mImm = (MemoryImmediate)op;
                    if (!ImmediateOk(addressWidth, mImm.UnsignedVal))
                    {
                        throw Ex(addressWidth);
                    }
                    immData = addressWidth switch
                    {
                        DataWidth.I8 => new List<byte>() { (byte)mImm.UnsignedVal },
                        DataWidth.I16 => new List<byte>(AdjustEndianness((ushort)mImm.UnsignedVal, endianness)),
                        DataWidth.I32 => new List<byte>(AdjustEndianness((uint)mImm.UnsignedVal, endianness)),
                        DataWidth.I64 => new List<byte>(AdjustEndianness(mImm.UnsignedVal, endianness)),
                        _ => throw Ex(addressWidth),
                    };
                    break;
                default:
                    throw new InvalidOperationException("Wrong operand type: " + op.Type);
            }
            return immData.ToArray();
        }

        public static (byte? planePrefix, byte? additionalModeByte, InstructionClass actualClass) GetPlanePrefixes(MnemonicType mnemonic, OperandType? firstType, OperandType? secondType)
        {
            byte? planePrefix = null;
            byte? additionalModeByte = null; // Доп. байт, кодирующий режим остальных двух операндов

            var classes = GetInstructionClasses(mnemonic);
            InstructionClass actualClass;
            switch (classes)
            {
                case InstructionClass.Basic:
                    return (null, null, InstructionClass.Basic);
                case InstructionClass.Op1:
                    if (firstType == null)
                    {
                        throw new InvalidOperationException("Must be one operand");
                    }
                    switch (firstType)
                    {
                        case OperandType.Immediate:
                        case OperandType.IdentifierOffset:
                            actualClass = InstructionClass.Op1Imm;
                            break;
                        default:
                            actualClass = InstructionClass.Op1;
                            break;
                    }
                    break;
                case InstructionClass.Op2Any:
                    if (secondType == null)
                    {
                        throw new InvalidOperationException("Must be two operands");
                    }
                    switch (secondType.Value)
                    {
                        case OperandType.Immediate:
                        case OperandType.IdentifierOffset:
                            actualClass = InstructionClass.Op2Imm;
                            break;
                        default:
                            actualClass = InstructionClass.Op2;
                            break;
                    }
                    break;
                case InstructionClass.All:
                    if (firstType == null)
                    {
                        return (null, null, InstructionClass.Basic); // Basic
                    }
                    else if (firstType != null && secondType == null)
                    {
                        switch (firstType)
                        {
                            case OperandType.Immediate:
                            case OperandType.IdentifierOffset:
                                actualClass = InstructionClass.Op1Imm;
                                break;
                            default:
                                actualClass = InstructionClass.Op1;
                                break;
                        }
                    }
                    else if (firstType != null && secondType != null)
                    {
                        switch (secondType.Value)
                        {
                            case OperandType.Immediate:
                            case OperandType.IdentifierOffset:
                                actualClass = InstructionClass.Op2Imm;
                                break;
                            default:
                                actualClass = InstructionClass.Op2;
                                break;
                        }
                    }
                    else
                    {
                        throw new InvalidOperationException("Wrong operand types");
                    }
                    break;
                default:
                    throw new InvalidOperationException("Wrong operand types");
            }

            switch (actualClass)
            {
                case InstructionClass.Basic:
                    return (null, null, InstructionClass.Basic);
                case InstructionClass.Op1:
                    planePrefix = OP1;
                    planePrefix |= GetOperandModeBits(firstType.Value, null);
                    break;
                case InstructionClass.Op1Imm:
                    planePrefix = OP1IMM;
                    break;
                case InstructionClass.Op2:
                    planePrefix = OP2;
                    planePrefix |= GetOperandModeBits(firstType.Value, secondType.Value);
                    break;
                case InstructionClass.Op2Imm:
                    planePrefix = OP2IMM;
                    planePrefix |= GetOperandModeBits(firstType.Value, secondType.Value);
                    break;
            }
            return (planePrefix, additionalModeByte, actualClass);
        }

        public static byte GetOpcode(InstrPlane plane, MnemonicType mnemonic)
        {
            return opcodes[(plane, mnemonic)];
        }

        public static (RegisterKind kind, byte num) ParseRegister(string regText)
        {
            regText = regText.ToUpperInvariant();
            try
            {
                if (regText.StartsWith("SR"))
                {
                    return (RegisterKind.System, byte.Parse(regText.Substring(2)));
                }
                else if (regText.StartsWith("IR"))
                {
                    return (RegisterKind.Informational, byte.Parse(regText.Substring(2)));
                }
                else if (regText.StartsWith("R"))
                {
                    return (RegisterKind.GeneralPurpose, byte.Parse(regText.Substring(1)));
                }
                else
                {
                    throw new InvalidOperationException("Wrong register format");
                }
            }
            catch (OverflowException e)
            {
                throw new InvalidOperationException("Wron register number, must be between 0 and 255", e);
            }
        }

        public static (byte, byte?) GetConditionalJmpPrefixes(OperandType type1, OperandType? type2)
        {
            byte jmpCond = (byte)(JMPCOND | GetOperandModeBits(type1, null));
            byte? jmpCond2 = null;
            if (type2 != null)
            {
                jmpCond2 = (byte)(JMPCOND | GetOperandModeBits(type2.Value, null));
            }
            return (jmpCond, jmpCond2);
        }

        public static byte GetConditionalSetPrefix(OperandType type)
        {
            return (byte)(CONDFLGST | GetOperandModeBits(type, null));
        }

        public static DataWidth GetDataAddressWidth(string dataTypeSpecifier)
        {
            if (!dataAddressWidths.TryGetValue(dataTypeSpecifier.ToUpperInvariant(), out var width))
            {
                throw new InvalidOperationException("Unknown data/address width: " + dataTypeSpecifier);
            }
            return width;
        }

        private static byte GetDataWidthBits(DataWidth dataWidth)
        {
            return dataWidth switch
            {
                DataWidth.I8 => 0b000,
                DataWidth.I16 => 0b001,
                DataWidth.I32 => 0b010,
                DataWidth.I64 => 0b011,
                _ => throw new InvalidOperationException("Unsupported data width: " + dataWidth),
            };
        }

        private static byte GetAddressWidthBits(DataWidth addressWidth)
        {
            return addressWidth switch
            {
                DataWidth.I8 => 0b111,
                DataWidth.I16 => 0b000,
                DataWidth.I32 => 0b001,
                DataWidth.I64 => 0b010,
                _ => throw new InvalidOperationException("Unsupported address width: " + addressWidth),
            };
        }

        public static (byte, byte?) GetDataTypePrefixes(DataWidth dataWidth, DataWidth addressWidth)
        {
            byte sz = SZ;
            byte? szsup = null;
            if (addressWidth == DataWidth.I8)
            {
                szsup = SZSUP | 0b10;
            }
            sz |= (byte)(GetDataWidthBits(dataWidth) | (GetAddressWidthBits(addressWidth) << 2));
            return (sz, szsup);
        }

        private static readonly Dictionary<string, DataWidth> dataAddressWidths = new Dictionary<string, DataWidth>()
        {
            { ".I8", DataWidth.I8 },
            { ".I16", DataWidth.I16 },
            { ".I32", DataWidth.I32 },
            { ".I64", DataWidth.I64 },
            { ".A8", DataWidth.I8 },
            { ".A16", DataWidth.I16 },
            { ".A32", DataWidth.I32 },
            { ".A64", DataWidth.I64 },
        };

        public static MnemonicType ParseMnemonic(string mnemonicText)
        {
            return mnemonicText.ToUpperInvariant() switch
            {
                "ADD" => MnemonicType.Add,
                "ADDO" => MnemonicType.Addo,
                "ALIGNLEFT" => MnemonicType.Alignleft,
                "ALIGNRIGHT" => MnemonicType.Alignright,
                "ALLOCVARS" => MnemonicType.Allocvars,
                "ALWINT" => MnemonicType.Alwint,
                "AND" => MnemonicType.And,
                "CALL" => MnemonicType.Call,
                "CALLNAT" => MnemonicType.Callnat,
                "CHNGMODE" => MnemonicType.Chngmode,
                "CLRST" => MnemonicType.Clrst,
                "CPY" => MnemonicType.Cpy,
                "CRSVPTR" => MnemonicType.Crsvptr,
                "DBGINT" => MnemonicType.Dbgint,
                "DECR" => MnemonicType.Decr,
                "DIV" => MnemonicType.Div,
                "FADD" => MnemonicType.Fadd,
                "FBDINT" => MnemonicType.Fbdint,
                "FDIV" => MnemonicType.Fdiv,
                "FILL" => MnemonicType.Fill,
                "FMUL" => MnemonicType.Fmul,
                "FSUB" => MnemonicType.Fsub,
                "FTRUNC" => MnemonicType.Ftrunc,
                "FTONTAFZ" => MnemonicType.Ftontafz,
                "FROTOPINF" => MnemonicType.Frotopinf,
                "FROTOMINF" => MnemonicType.Frotominf,
                "FWCALL" => MnemonicType.Fwcall,
                "GETBIT" => MnemonicType.Getbit,
                "GETCDPTR" => MnemonicType.Getcdptr,
                "GETCTXSC" => MnemonicType.Getctxsz,
                "GETFROMD" => MnemonicType.Getfromd,
                "GETINTFLAG" => MnemonicType.Getintflag,
                "GETIP" => MnemonicType.Getip,
                "GETRETPTR" => MnemonicType.Getretptr,
                "GETSTREG" => MnemonicType.Getstreg,
                "IDIV" => MnemonicType.Idiv,
                "INCR" => MnemonicType.Incr,
                "INT" => MnemonicType.Int,
                "INVALID" => MnemonicType.Invalid,
                "INVBIT" => MnemonicType.Invbit,
                "IRET" => MnemonicType.Iret,
                "JMP" => MnemonicType.Jmp,
                "JMPNAT" => MnemonicType.Jmpnat,
                "JUMPIF" => MnemonicType.Jumpif,
                "LOADCTX" => MnemonicType.Loadctx,
                "MOVSX" => MnemonicType.Movsx,
                "MOVZX" => MnemonicType.Movzx,
                "MUL" => MnemonicType.Mul,
                "MULO" => MnemonicType.Mulo,
                "CMP" => MnemonicType.Cmp,
                "NEG" => MnemonicType.Neg,
                "NOP" => MnemonicType.Nop,
                "NOR" => MnemonicType.Nor,
                "NOT" => MnemonicType.Not,
                "OR" => MnemonicType.Or,
                "POP" => MnemonicType.Pop,
                "PRRDSTATREG" => MnemonicType.Prrdstatreg,
                "PUSH" => MnemonicType.Push,
                "RDINFOREG" => MnemonicType.Rdinforeg,
                "RDPORT" => MnemonicType.Rdport,
                "RDSTATREG" => MnemonicType.Rdstatreg,
                "RDSYSREG" => MnemonicType.Rdsysreg,
                "RDTCKS" => MnemonicType.Rdtcks,
                "RET" => MnemonicType.Ret,
                "RTL" => MnemonicType.Rtl,
                "RTR" => MnemonicType.Rtr,
                "SAR" => MnemonicType.Sar,
                "SAVECTX" => MnemonicType.Savectx,
                "SETBIT" => MnemonicType.Setbit,
                "SETRETPTR" => MnemonicType.Setretptr,
                "SETROMD" => MnemonicType.Setfromd,
                "SETSTREG" => MnemonicType.Setstreg,
                "SHL" => MnemonicType.Shl,
                "SHR" => MnemonicType.Shr,
                "SMCODEND" => MnemonicType.Smcodend,
                "SMCODST" => MnemonicType.Smcodst,
                "SUB" => MnemonicType.Sub,
                "SUBO" => MnemonicType.Subo,
                "SYSCALL" => MnemonicType.Syscall,
                "SYSID" => MnemonicType.Sysid,
                "WRPORT" => MnemonicType.Wrport,
                "WRSYSREG" => MnemonicType.Wrsysreg,
                "XOR" => MnemonicType.Xor,
                "ZERO" => MnemonicType.Zero,
                "RESTREG" => MnemonicType.Restreg,
                "STRREG" => MnemonicType.Strreg,
                "JMPUSR" => MnemonicType.Jmpusr,
                "GETCAPTR" => MnemonicType.Getcaptr,
                "FTONTTE" => MnemonicType.Ftontte,
                "CPYZX" => MnemonicType.Cpyzx,
                "CPYSZ" => MnemonicType.Cpyzx,
                _ => throw new InvalidOperationException("Unknown mnemonic: " + mnemonicText),
            };
        }

        private static byte GetCpyxOpSizes(DataWidth first, DataWidth second)
        {
            if (first == DataWidth.I8 && second == DataWidth.I16)
            {
                return 0x0;
            }
            else if (first == DataWidth.I8 && second == DataWidth.I32)
            {
                return 0x1;
            }
            else if (first == DataWidth.I8 && second == DataWidth.I64)
            {
                return 0x2;
            }
            else if (first == DataWidth.I16 && second == DataWidth.I32)
            {
                return 0x5;
            }
            else if (first == DataWidth.I16 && second == DataWidth.I64)
            {
                return 0x06;
            }
            else if (first == DataWidth.I32 && second == DataWidth.I64)
            {
                return 0x9;
            }
            else
            {
                throw new InvalidOperationException($"Unsupported CPYZX/CPYSX data widths: {first} and {second}");
            }
        }

        public static (byte, byte) GetCpyxOpcodeAndField(bool signExtended, DataWidth firstWidth, DataWidth secondWidth, OperandType firstOperandType, OperandType secondOperandType)
        {
            if (firstWidth == secondWidth)
            {
                throw new InvalidOperationException("CPYZX/CPYSX data widths must be different");
            }
            byte opcode = signExtended ? CPYSZ : CPYZX;
            byte field = 0;
            if (firstWidth > secondWidth)
            {
                // Первый операнд - приёмник, поэтому сужение
                field |= CPYX_NARROW;
            }
            byte szchg = GetCpyxOpSizes(firstWidth, secondWidth);
            if ((szchg & 0b0001) == 0b0001)
            {
                field |= 0b10000000;
            }
            szchg >>= 1;
            opcode |= szchg;
            field |= GetOperandModeBits(firstOperandType, secondOperandType);
            return (opcode, field);
        }

        public static ulong ParseInteger(string text)
        {
            static string ErrorMsg(string text)
            {
                return "Value is not correct: " + text;
            }

            IntegerType type;
            if (text.StartsWith('-') || text.StartsWith('+'))
            {
                type = IntegerType.Decimal;
            }
            else if (text.ToUpperInvariant().StartsWith("0X"))
            {
                type = IntegerType.Hexadecimal;
            }
            else if (text.ToUpperInvariant().StartsWith("0B"))
            {
                type = IntegerType.Binary;
            }
            else
            {
                type = IntegerType.Decimal;
            }

            ulong value;
            switch (type)
            {
                case IntegerType.Binary:
                    string stripped = text.Trim().Remove(0, 2);
                    try
                    {
                        value = Convert.ToUInt64(stripped, 2);
                    }
                    catch (Exception e)
                    {
                        throw new InvalidOperationException(ErrorMsg(text), e);
                    }
                    break;
                case IntegerType.Decimal:
                    stripped = text.Trim().Replace("+", null);
                    if (stripped[0] == '-')
                    {
                        if (!long.TryParse(stripped, out long signedVal))
                        {
                            throw new InvalidOperationException(ErrorMsg(text));
                        }
                        value = (ulong)signedVal;
                    }
                    else
                    {
                        if (!ulong.TryParse(stripped, out ulong tmp))
                        {
                            throw new InvalidOperationException(ErrorMsg(text));
                        }
                        value = tmp;
                    }
                    break;
                case IntegerType.Hexadecimal:
                    stripped = text.Trim().Remove(0, 2);
                    try
                    {
                        value = Convert.ToUInt64(stripped, 16);
                    }
                    catch (Exception e)
                    {
                        throw new InvalidOperationException(ErrorMsg(text), e);
                    }
                    break;
                default:
                    throw new InvalidOperationException("Wrong integer type: " + type);
            }
            return value;
        }

        public static InstructionConditionTokenType ParseCondition(string condition)
        {
            if (!conds.TryGetValue(condition.ToUpperInvariant(), out var val))
            {
                throw new InvalidOperationException("Unknown condition: " + val);
            }
            return val;
        }

        public static byte GetCondition(InstructionConditionTokenType type)
        {
            switch (type)
            {
                case InstructionConditionTokenType.Zer:
                case InstructionConditionTokenType.Equal:
                case InstructionConditionTokenType.Umin:
                    return 0x00;
                case InstructionConditionTokenType.Nzer:
                case InstructionConditionTokenType.Nequal:
                case InstructionConditionTokenType.Numin:
                    return 0x01;
                case InstructionConditionTokenType.Negative:
                    return 0x02;
                case InstructionConditionTokenType.Positive:
                    return 0x03;
                case InstructionConditionTokenType.Carry:
                case InstructionConditionTokenType.Uless:
                    return 0x04;
                case InstructionConditionTokenType.Ncarry:
                case InstructionConditionTokenType.Ugreatereq:
                    return 0x05;
                case InstructionConditionTokenType.Ovf:
                    return 0x06;
                case InstructionConditionTokenType.Novf:
                    return 0x07;
                case InstructionConditionTokenType.Ulesseq:
                    return 0x08;
                case InstructionConditionTokenType.Ugreater:
                    return 0x09;
                case InstructionConditionTokenType.Sless:
                    return 0x0A;
                case InstructionConditionTokenType.Sgreatereq:
                    return 0x0B;
                case InstructionConditionTokenType.Slesseq:
                    return 0x0C;
                case InstructionConditionTokenType.Sgreater:
                    return 0x0D;
                case InstructionConditionTokenType.Parity:
                case InstructionConditionTokenType.ParityEven:
                    return 0x0E;
                case InstructionConditionTokenType.Nparity:
                case InstructionConditionTokenType.ParityOdd:
                    return 0x0F;
                case InstructionConditionTokenType.Halfcarry:
                    return 0x10;
                case InstructionConditionTokenType.Nhalfcarry:
                    return 0x11;
                case InstructionConditionTokenType.Umax:
                case InstructionConditionTokenType.Minusone:
                    return 0x12;
                case InstructionConditionTokenType.Numax:
                case InstructionConditionTokenType.Nminusone:
                    return 0x13;
                case InstructionConditionTokenType.Smax:
                    return 0x14;
                case InstructionConditionTokenType.Nsmax:
                    return 0x15;
                case InstructionConditionTokenType.Smin:
                    return 0x16;
                case InstructionConditionTokenType.Nsmin:
                    return 0x17;
                case InstructionConditionTokenType.One:
                    return 0x18;
                case InstructionConditionTokenType.Notone:
                    return 0x19;
                case InstructionConditionTokenType.True:
                    return 0xFE;
                case InstructionConditionTokenType.False:
                    return 0xFF;
                default:
                    throw new InvalidOperationException("Unknown condition: " + type);
            }
        }

        private static Dictionary<string, InstructionConditionTokenType> conds = new Dictionary<string, InstructionConditionTokenType>()
        {
            { "ZER", InstructionConditionTokenType.Zer },
                { "NZER", InstructionConditionTokenType.Nzer },
                { "NEGATIVE", InstructionConditionTokenType.Negative },
                { "POSITIVE", InstructionConditionTokenType.Positive },
                { "CARRY", InstructionConditionTokenType.Carry },
                { "NCARRY", InstructionConditionTokenType.Ncarry },
                { "OVF", InstructionConditionTokenType.Ovf },
                { "NOVF", InstructionConditionTokenType.Novf },
                { "EQUAL", InstructionConditionTokenType.Equal },
                { "NEQUAL", InstructionConditionTokenType.Nequal },
                { "ULESS", InstructionConditionTokenType.Uless },
                { "UGREATEREQ", InstructionConditionTokenType.Ugreatereq },
                { "ULESSEQ", InstructionConditionTokenType.Ulesseq },
                { "UGREATER", InstructionConditionTokenType.Ugreater },
                { "SLESS", InstructionConditionTokenType.Sless },
                { "SGREATEREQ", InstructionConditionTokenType.Sgreatereq },
                { "SLESSEQ", InstructionConditionTokenType.Slesseq },
                { "SGREATER", InstructionConditionTokenType.Sgreater },
                { "PARITY", InstructionConditionTokenType.Parity },
            { "PARITYEVEN", InstructionConditionTokenType.ParityEven },
            { "PARITYODD", InstructionConditionTokenType.ParityOdd },
                { "NPARITY", InstructionConditionTokenType.Nparity },
                { "HALFCARRY", InstructionConditionTokenType.Halfcarry },
                { "NHANFCARRY", InstructionConditionTokenType.Nhalfcarry },
                { "UMAX", InstructionConditionTokenType.Umax },
                { "NUMAX", InstructionConditionTokenType.Numax },
                { "UMIN", InstructionConditionTokenType.Umin },
                { "NUMIN", InstructionConditionTokenType.Numin },
                { "MINUSONE", InstructionConditionTokenType.Minusone },
                { "NMINUSONE", InstructionConditionTokenType.Nminusone },
                { "SMAX", InstructionConditionTokenType.Smax },
                { "NSMAX", InstructionConditionTokenType.Nsmax },
                { "SMIN", InstructionConditionTokenType.Smin },
                { "NSMIN", InstructionConditionTokenType.Nsmin },
                { "ONE", InstructionConditionTokenType.One },
                { "NOTONE", InstructionConditionTokenType.Notone },
                { "TRUE", InstructionConditionTokenType.True },
                { "FALSE", InstructionConditionTokenType.False },
        };

        public static byte[] AdjustEndianness(ulong data, Endianness endiannessToSet)
        {
            byte[] dataBytes = BitConverter.GetBytes(data);
            if (endiannessToSet == Endianness.LittleEndian && !BitConverter.IsLittleEndian ||
                endiannessToSet == Endianness.BigEndian && BitConverter.IsLittleEndian)
            {
                Array.Reverse(dataBytes);
            }
            return dataBytes;
        }

        public static byte[] AdjustEndianness(uint data, Endianness endiannessToSet)
        {
            byte[] dataBytes = BitConverter.GetBytes(data);
            if (endiannessToSet == Endianness.LittleEndian && !BitConverter.IsLittleEndian ||
                endiannessToSet == Endianness.BigEndian && BitConverter.IsLittleEndian)
            {
                Array.Reverse(dataBytes);
            }
            return dataBytes;
        }

        public static byte[] AdjustEndianness(ushort data, Endianness endiannessToSet)
        {
            byte[] dataBytes = BitConverter.GetBytes(data);
            if (endiannessToSet == Endianness.LittleEndian && !BitConverter.IsLittleEndian ||
                endiannessToSet == Endianness.BigEndian && BitConverter.IsLittleEndian)
            {
                Array.Reverse(dataBytes);
            }
            return dataBytes;
        }

        static Dictionary<(InstrPlane, MnemonicType), byte> opcodes = new Dictionary<(InstrPlane, MnemonicType), byte>()
        {
            { (InstrPlane.Basic, MnemonicType.Invalid), 0 },
            { (InstrPlane.Basic, MnemonicType.Nop), 1 },
            { (InstrPlane.Basic, MnemonicType.Ret), 2 },
            { (InstrPlane.Basic, MnemonicType.Syscall), 3 },
            { (InstrPlane.Basic, MnemonicType.Chngmode), 5 },
            { (InstrPlane.Basic, MnemonicType.Smcodst), 6 },
            { (InstrPlane.Basic, MnemonicType.Smcodend), 7 },
            { (InstrPlane.Basic, MnemonicType.Sysid), 8 },
            { (InstrPlane.Basic, MnemonicType.Allocvars), 0xA },
            { (InstrPlane.Basic, MnemonicType.Dbgint), 0xB },
            { (InstrPlane.Basic, MnemonicType.Getretptr), 0xC },
            { (InstrPlane.Basic, MnemonicType.Setretptr), 0xD },
            { (InstrPlane.Basic, MnemonicType.Clrst), 0xE },
            { (InstrPlane.Basic, MnemonicType.Getcdptr), 0xF },
            { (InstrPlane.Basic, MnemonicType.Cpyzx), 0x10 },
            { (InstrPlane.Basic, MnemonicType.Cpysx), 0x18 },
            { (InstrPlane.Basic, MnemonicType.Loadctx), 0x69 },
            { (InstrPlane.Basic, MnemonicType.Savectx), 0x6A },

            { (InstrPlane.Priv, MnemonicType.Invalid), 0 },
            { (InstrPlane.Priv, MnemonicType.Nop), 1 },
            { (InstrPlane.Priv, MnemonicType.Callnat), 2 },
            { (InstrPlane.Priv, MnemonicType.Jmpnat), 3 },
            { (InstrPlane.Priv, MnemonicType.Rdinforeg), 4 },
            { (InstrPlane.Priv, MnemonicType.Fwcall), 5 },
            { (InstrPlane.Priv, MnemonicType.Jmpusr), 6 },
            { (InstrPlane.Priv, MnemonicType.Rdsysreg), 7 },
            { (InstrPlane.Priv, MnemonicType.Wrsysreg), 8 },
            { (InstrPlane.Priv, MnemonicType.Rdport), 9 },
            { (InstrPlane.Priv, MnemonicType.Wrport), 0xA },
            { (InstrPlane.Priv, MnemonicType.Prrdstatreg), 0xB },
            { (InstrPlane.Priv, MnemonicType.Fbdint), 0xC },
            { (InstrPlane.Priv, MnemonicType.Alwint), 0xD },
            { (InstrPlane.Priv, MnemonicType.Getintflag), 0xE },
            { (InstrPlane.Priv, MnemonicType.Iret), 0xF },
            { (InstrPlane.Priv, MnemonicType.Restreg), 0x10 },
            { (InstrPlane.Priv, MnemonicType.Strreg), 0x11 },

            { (InstrPlane.Op1, MnemonicType.Invalid), 0 },
            { (InstrPlane.Op1, MnemonicType.Nop), 1 },
            { (InstrPlane.Op1, MnemonicType.Call), 2 },
            { (InstrPlane.Op1, MnemonicType.Zero), 4 },
            { (InstrPlane.Op1, MnemonicType.Fill), 5 },
            { (InstrPlane.Op1, MnemonicType.Not), 6 },
            { (InstrPlane.Op1, MnemonicType.Neg), 7 },
            { (InstrPlane.Op1, MnemonicType.Shr), 8 },
            { (InstrPlane.Op1, MnemonicType.Shl), 9 },
            { (InstrPlane.Op1, MnemonicType.Sar), 0xA },
            { (InstrPlane.Op1, MnemonicType.Rtr), 0xB },
            { (InstrPlane.Op1, MnemonicType.Rtl), 0xC },
            { (InstrPlane.Op1, MnemonicType.Incr), 0xE },
            { (InstrPlane.Op1, MnemonicType.Decr), 0xF },
            { (InstrPlane.Op1, MnemonicType.Push), 0x10 },
            { (InstrPlane.Op1, MnemonicType.Pop), 0x11 },
            { (InstrPlane.Op1, MnemonicType.Alignleft), 0x12 },
            { (InstrPlane.Op1, MnemonicType.Alignright), 0x13 },
            { (InstrPlane.Op1, MnemonicType.Getfromd), 0x14 },
            { (InstrPlane.Op1, MnemonicType.Setfromd), 0x15 },
            { (InstrPlane.Op1, MnemonicType.Rdtcks), 0x16 },
            { (InstrPlane.Op1, MnemonicType.Getip), 0x17 },
            { (InstrPlane.Op1, MnemonicType.Getstreg), 0x18 },
            { (InstrPlane.Op1, MnemonicType.Setstreg), 0x19 },
            { (InstrPlane.Op1, MnemonicType.Jmp), 0x1A },
            { (InstrPlane.Op1, MnemonicType.Getctxsz), 0x1B },
            { (InstrPlane.Op1, MnemonicType.Getcaptr), 0x1C },
            { (InstrPlane.Op1, MnemonicType.Ftrunc), 0x80 },
            { (InstrPlane.Op1, MnemonicType.Ftontte), 0x81 },
            { (InstrPlane.Op1, MnemonicType.Ftontafz), 0x82 },
            { (InstrPlane.Op1, MnemonicType.Frotopinf), 0x83 },
            { (InstrPlane.Op1, MnemonicType.Frotominf), 0x84 },
            { (InstrPlane.Op1, MnemonicType.Rdstatreg), 0xF0 },

            { (InstrPlane.Op1Imm, MnemonicType.Invalid), 0 },
            { (InstrPlane.Op1Imm, MnemonicType.Nop), 0 },
            { (InstrPlane.Op1Imm, MnemonicType.Push), 0 },
            { (InstrPlane.Op1Imm, MnemonicType.Setstreg), 0 },

            { (InstrPlane.Op2, MnemonicType.Invalid), 0 },
            { (InstrPlane.Op2, MnemonicType.Nop), 1 },
            { (InstrPlane.Op2, MnemonicType.Add), 2 },
            { (InstrPlane.Op2, MnemonicType.Sub), 3 },
            { (InstrPlane.Op2, MnemonicType.Mul), 4 },
            { (InstrPlane.Op2, MnemonicType.Div), 5 },
            { (InstrPlane.Op2, MnemonicType.Idiv), 6 },
            { (InstrPlane.Op2, MnemonicType.And), 7 },
            { (InstrPlane.Op2, MnemonicType.Or), 8 },
            { (InstrPlane.Op2, MnemonicType.Xor), 9 },
            { (InstrPlane.Op2, MnemonicType.Nor), 0xA },
            { (InstrPlane.Op2, MnemonicType.Shl), 0xB },
            { (InstrPlane.Op2, MnemonicType.Shr), 0xC },
            { (InstrPlane.Op2, MnemonicType.Sar), 0xD },
            { (InstrPlane.Op2, MnemonicType.Addo), 0xE },
            { (InstrPlane.Op2, MnemonicType.Subo), 0xF },
            { (InstrPlane.Op2, MnemonicType.Mulo), 0x10 },
            { (InstrPlane.Op2, MnemonicType.Cmp), 0x11 },
            { (InstrPlane.Op2, MnemonicType.Getbit), 0x12 },
            { (InstrPlane.Op2, MnemonicType.Setbit), 0x13 },
            { (InstrPlane.Op2, MnemonicType.Invbit), 0x14 },
            { (InstrPlane.Op2, MnemonicType.Jumpif), 0x15 },
            { (InstrPlane.Op2, MnemonicType.Cpy), 0x16 },
            { (InstrPlane.Op2, MnemonicType.Rem), 0x17 },
            { (InstrPlane.Op2, MnemonicType.Irem), 0x18 },
            { (InstrPlane.Op2, MnemonicType.Nand), 0x19 },
            { (InstrPlane.Op2, MnemonicType.Rtl), 0x1A },
            { (InstrPlane.Op2, MnemonicType.Rtr), 0x1B },
            { (InstrPlane.Op2, MnemonicType.Adds), 0x20 },
            { (InstrPlane.Op2, MnemonicType.Subs), 0x21 },
            { (InstrPlane.Op2, MnemonicType.Muls), 0x22 },
            { (InstrPlane.Op2, MnemonicType.Addss), 0x23 },
            { (InstrPlane.Op2, MnemonicType.Subss), 0x24 },
            { (InstrPlane.Op2, MnemonicType.Mulss), 0x25 },
            { (InstrPlane.Op2, MnemonicType.Getefad), 0x26 },
            { (InstrPlane.Op2, MnemonicType.Fadd), 0x80 },
            { (InstrPlane.Op2, MnemonicType.Fsub), 0x81 },
            { (InstrPlane.Op2, MnemonicType.Fmul), 0x82 },
            { (InstrPlane.Op2, MnemonicType.Fdiv), 0x83 },

            { (InstrPlane.Op2Imm, MnemonicType.Invalid), 0 },
            { (InstrPlane.Op2Imm, MnemonicType.Nop), 1 },
            { (InstrPlane.Op2Imm, MnemonicType.Add), 2 },
            { (InstrPlane.Op2Imm, MnemonicType.Sub), 3 },
            { (InstrPlane.Op2Imm, MnemonicType.Mul), 4 },
            { (InstrPlane.Op2Imm, MnemonicType.Div), 5 },
            { (InstrPlane.Op2Imm, MnemonicType.Idiv), 6 },
            { (InstrPlane.Op2Imm, MnemonicType.And), 7 },
            { (InstrPlane.Op2Imm, MnemonicType.Or), 8 },
            { (InstrPlane.Op2Imm, MnemonicType.Xor), 9 },
            { (InstrPlane.Op2Imm, MnemonicType.Nor), 0xA },
            { (InstrPlane.Op2Imm, MnemonicType.Shl), 0xB },
            { (InstrPlane.Op2Imm, MnemonicType.Shr), 0xC },
            { (InstrPlane.Op2Imm, MnemonicType.Sar), 0xD },
            { (InstrPlane.Op2Imm, MnemonicType.Addo), 0xE },
            { (InstrPlane.Op2Imm, MnemonicType.Subo), 0xF },
            { (InstrPlane.Op2Imm, MnemonicType.Mulo), 0x10 },
            { (InstrPlane.Op2Imm, MnemonicType.Cmp), 0x11 },
            { (InstrPlane.Op2Imm, MnemonicType.Getbit), 0x12 },
            { (InstrPlane.Op2Imm, MnemonicType.Setbit), 0x13 },
            { (InstrPlane.Op2Imm, MnemonicType.Invbit), 0x14 },
            { (InstrPlane.Op2Imm, MnemonicType.Jumpif), 0x15 },
            { (InstrPlane.Op2Imm, MnemonicType.Cpy), 0x16 },
            { (InstrPlane.Op2Imm, MnemonicType.Rem), 0x17 },
            { (InstrPlane.Op2Imm, MnemonicType.Irem), 0x18 },
            { (InstrPlane.Op2Imm, MnemonicType.Nand), 0x19 },
            { (InstrPlane.Op2Imm, MnemonicType.Rtl), 0x1A },
            { (InstrPlane.Op2Imm, MnemonicType.Rtr), 0x1B },
            { (InstrPlane.Op2Imm, MnemonicType.Adds), 0x20 },
            { (InstrPlane.Op2Imm, MnemonicType.Subs), 0x21 },
            { (InstrPlane.Op2Imm, MnemonicType.Muls), 0x22 },
            { (InstrPlane.Op2Imm, MnemonicType.Addss), 0x23 },
            { (InstrPlane.Op2Imm, MnemonicType.Subss), 0x24 },
            { (InstrPlane.Op2Imm, MnemonicType.Mulss), 0x25 },
            { (InstrPlane.Op2Imm, MnemonicType.Getefad), 0x26 },
            { (InstrPlane.Op2Imm, MnemonicType.Fadd), 0x80 },
            { (InstrPlane.Op2Imm, MnemonicType.Fsub), 0x81 },
            { (InstrPlane.Op2Imm, MnemonicType.Fmul), 0x82 },
            { (InstrPlane.Op2Imm, MnemonicType.Fdiv), 0x83 },
        };
    }
}
