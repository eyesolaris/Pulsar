using Antlr4.Runtime.Misc;
using Antlr4.Runtime.Tree;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PulsarAssembler
{
    enum ElementType
    {
        Instruction,
        Procedure,
        DataDefinitionStatement,
    }

    /// <summary>
    /// Класс, позволяющий описывать смещение элемента,
    /// у которого есть идентификатор, в бинарном файле
    /// </summary>
    class ElementOffsets
    {
        Dictionary<IParseTree, string> nodeToId;
        Dictionary<string, IParseTree> idToNode;

        public ElementOffsets(IParseTree node)
        {

        }
    }

    struct IdentifierProps
    {
        public IdentifierProps(IParseTree node, ElementType type)
        {
            this.node = node;
            this.type = type;
        }

        public IParseTree node;
        public ElementType type;
    }

    struct ElementIds
    {
        public ElementIds(Dictionary<string, IdentifierProps> idToNode, Dictionary<IParseTree, (string, uint offset, IdentifierProps)> nodeToId)
        {
            this.idToNode = idToNode;
            this.nodeToId = nodeToId;
        }

        public Dictionary<string, IdentifierProps> idToNode;
        public Dictionary<IParseTree, (string, uint offset, IdentifierProps)> nodeToId;
    }

    class PulsarAsmCodeGenerator : PulsarAsmGrammarBaseListener
    {
        // object: ValueTuple<IParseTree, Dictionary<string, object>>
        Dictionary<string, IdentifierProps> idToNode = new Dictionary<string, IdentifierProps>();
        Dictionary<IParseTree, (string, uint, IdentifierProps)> nodeToId = new Dictionary<IParseTree, (string, uint, IdentifierProps)>();

        // Смещения идентификаторов с начала образа программы
        Dictionary<string, uint> offsets = new Dictionary<string, uint>();
        uint currentOffset = 4; // Учитываем, что сначала идут 4 байта MAGIC

        string curLabelName;

        bool inProcedure = false;

        Endianness currentEnd = Endianness.LittleEndian;
        DataWidth dataWidth = DataWidth.I32;
        DataWidth addressWidth = DataWidth.I32;

        List<IAsmElement> Elements = new List<IAsmElement>();

        public ElementIds GetIdsBlock()
        {
            return new ElementIds(idToNode, nodeToId);
        }

        public override void EnterProcedure([NotNull] PulsarAsmGrammarParser.ProcedureContext context)
        {
            inProcedure = true;
            Procedure proc = new Procedure(context, currentOffset, currentEnd, dataWidth, addressWidth);
            ParseTreeWalker.Default.Walk(proc, context);
            idToNode.Add(proc.Name, new IdentifierProps(context, ElementType.Procedure));
            nodeToId.Add(context, (proc.Name, currentOffset, new IdentifierProps(context, ElementType.Procedure)));
            offsets.Add(proc.Name, currentOffset);
            currentOffset += (uint)proc.TotalBytesCount;
            Elements.Add(proc);
        }

        public override void ExitProcedure([NotNull] PulsarAsmGrammarParser.ProcedureContext context)
        {
            inProcedure = false;
        }

        public override void EnterData_definition_statement([NotNull] PulsarAsmGrammarParser.Data_definition_statementContext context)
        {
            if (inProcedure)
            {
                return;
            }
            DataElement data = new DataElement(context, currentEnd);
            ParseTreeWalker.Default.Walk(data, context);
            Elements.Add(data);
            if (data.Id != null)
            {
                idToNode.Add(data.Id, new IdentifierProps(context, ElementType.Instruction));
                offsets.Add(data.Id, currentOffset);
            }
            nodeToId.Add(context, (data.Id, currentOffset, new IdentifierProps(context, ElementType.Instruction)));
            currentOffset += (uint)data.TotalBytesCount;
        }

        public override void EnterInstruction([NotNull] PulsarAsmGrammarParser.InstructionContext context)
        {
            if (inProcedure)
            {
                return;
            }    
            InstructionElement instr = new InstructionElement(context, currentEnd, dataWidth, addressWidth);
            ParseTreeWalker.Default.Walk(instr, context);
            Elements.Add(instr);
            if (instr.Label != null)
            {
                idToNode.Add(instr.Label, new IdentifierProps(context, ElementType.Instruction));
                offsets.Add(instr.Label, currentOffset);
            }
            nodeToId.Add(context, (instr.Label, currentOffset, new IdentifierProps(context, ElementType.Instruction)));
            currentOffset += (uint)instr.TotalBytesCount;
        }

        public override void EnterDirective([NotNull] PulsarAsmGrammarParser.DirectiveContext context)
        {
            if (context.ENDIANNESS_BIG() != null)
            {
                currentEnd = Endianness.BigEndian;
            }
            else if (context.ENDIANNESS_LITTLE() != null)
            {
                currentEnd = Endianness.LittleEndian;
            }
            else if (context.bitness_directive() != null)
            {
                var bitness = context.bitness_directive();
                dataWidth = InstructionEncoding.GetDataAddressWidth(".I" + bitness.DECIMAL_INTEGER().GetText());
                addressWidth = dataWidth;
            }
            else if (context.address_directive() != null)
            {
                var addresses = context.address_directive();
                addressWidth = InstructionEncoding.GetDataAddressWidth(".A" + addresses.DECIMAL_INTEGER().GetText());
            }
        }

        public override void ExitAsm_file([NotNull] PulsarAsmGrammarParser.Asm_fileContext context)
        {
            var ids = GetIdsBlock();
            // Второй проход
            foreach (IAsmElement elem in Elements)
            {
                if (elem is InstructionElement i)
                {
                    uint itsOffset = ids.nodeToId[i.Node].offset;
                    i.ResolveIdentifiers(ids, itsOffset);
                }
                else if (elem is Procedure p)
                {
                    p.ResolveIdentifiers(GetIdsBlock());
                }
            }
        }

        public void EmitBinary(Stream stream)
        {
            const uint PULSAR_MAGIC = 0xD840F7F7;
            byte[] magicBytes = BitConverter.GetBytes(PULSAR_MAGIC);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(magicBytes);
            }
            stream.Write(magicBytes);
            foreach (var d in Elements)
            {
                foreach (IReadOnlyList<byte> bytes in (IEnumerable<IReadOnlyList<byte>>)d)
                {
                    stream.Write(bytes.ToArray());
                }
            }
        }
    }
}
