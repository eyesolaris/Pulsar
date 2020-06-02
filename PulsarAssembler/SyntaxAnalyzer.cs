using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Misc;
using PulsarAssembler.Tokens;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace PulsarAssembler
{
    namespace Syntax
    {
        public class SyntaxAnalizerException : Exception
        {
            public SyntaxAnalizerException(string message)
                : base(message)
            {
            }

            public SyntaxAnalizerException(string message, Exception inner)
                : base(message, inner)
            {
            }

            public SyntaxAnalizerException(Symbol erroneousSymbol, string message)
                : base($"Line {erroneousSymbol.LineNumber}, symbol {erroneousSymbol.SymbolNumber}: " +
                      message ?? "ошибочный символ")
            {
            }
        }

        public class SyntaxAnalyzer
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="tokenStream"></param>
            /// <exception cref="SyntaxAnalizerException"></exception>
            public static void CollapseProductions(LinkedList<Symbol> tokenStream)
            {
                Console.WriteLine("Syntax analizer started...");
                try
                {
                    SymbolRuleStore.CollapseSymbols(tokenStream);
                }
                catch (Exception e)
                {
                    throw new SyntaxAnalizerException("Can't collapse productions", e);
                }
            }

            /// <summary>
            /// Уровень вложенности текущего правила
            /// </summary>
            internal static int Level = 0;

            internal static string LastRule = string.Empty;
        }

        public enum SymbolType
        {
            Terminal,
            NonTerminal,
        }

        public abstract class Symbol : IReadOnlyList<Symbol>
        {
            protected Symbol(SymbolType type)
            {
                SymbolType = type;
            }

            public SymbolType SymbolType { get; }

            public abstract Enum SymbolIdentifier { get; }
            public abstract Enum SymbolSubidentifier { get; }

            public abstract IReadOnlyList<Symbol> ChildSymbols { get; }

            public static bool TryParseSymbol(IReadOnlyList<Token> tokens, int startIndex)
            {
                return false;
            }

            public IEnumerator<Symbol> GetEnumerator()
            {
                return ChildSymbols.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return ChildSymbols.GetEnumerator();
            }

            public abstract uint LineNumber { get; }

            public abstract uint SymbolNumber { get; }

            public int Count => ChildSymbols.Count;

            public Symbol this[int index] => ChildSymbols[index];
        }

        public abstract class NonTerminalSymbol : Symbol
        {
            protected NonTerminalSymbol()
                : base(SymbolType.NonTerminal)
            {
            }

            public override sealed uint LineNumber => ChildSymbols[0].LineNumber;

            public override sealed uint SymbolNumber => ChildSymbols[0].SymbolNumber;

            public override string ToString()
            {
                StringBuilder sb = new StringBuilder();
                foreach (var sym in ChildSymbols)
                {
                    sb.Append(sym.ToString());
                }
                return sb.ToString();
            }
        }

        public enum NonTerminalType
        {
            BitnessDirectives,
            EndiannessDirectives,
            Proc,
            Operand,
            Instruction,
            DataDefinition,
            AsmFile,
        }

        public enum BitnessDirectiveType
        {
            Data,
            Address,
        }

        

        public enum OffsetSign
        {
            Minus,
            Plus,
        }

        

        public enum InstructionType
        {
            Unconditional,
            ConditionalBranch,
            ConditionalWrite,
        }

        public class BitnessDirectiveSymbol : NonTerminalSymbol
        {
            public BitnessDirectiveSymbol(
                DirectiveToken directive,
                IntegerToken bitness)
            {
                symbols.Add(directive);
                symbols.Add(bitness);
                Directive = directive.DirectiveType switch
                {
                    DirectiveType.OperandSize => BitnessDirectiveType.Data,
                    DirectiveType.AddressSize => BitnessDirectiveType.Address,
                    _ => throw new InvalidOperationException($"Wrong directive type: {directive.DirectiveType}"),
                };
                Bitness = bitness.UnsignedValue switch
                {
                    8 => DataWidth.Byte,
                    16 => DataWidth.Word,
                    32 => DataWidth.Dword,
                    64 => DataWidth.Qword,
                    _ => throw new InvalidOperationException($"Invalid bitness: {bitness.UnsignedValue}"),
                };
            }

            public DataWidth Bitness { get; }

            public BitnessDirectiveType Directive { get; }

            public override Enum SymbolIdentifier => NonTerminalType.BitnessDirectives;

            public override Enum SymbolSubidentifier => Directive;

            private readonly List<Symbol> symbols = new List<Symbol>();
            public override IReadOnlyList<Symbol> ChildSymbols { get => symbols; }
        }

        public class EndiannessDirective : NonTerminalSymbol
        {
            public EndiannessDirective(DirectiveToken directive)
            {
                if (directive.DirectiveType == DirectiveType.LittleEndian)
                {
                    Endianness = Endianness.LittleEndian;
                }
                else if (directive.DirectiveType == DirectiveType.BigEndian)
                {
                    Endianness = Endianness.BigEndian;
                }
                else
                {
                    throw new InvalidOperationException("Wrong directive type: " + directive.DirectiveType);
                }
            }

            public Endianness Endianness { get; }

            public override Enum SymbolIdentifier => NonTerminalType.EndiannessDirectives;

            public override Enum SymbolSubidentifier => Endianness;

            public override IReadOnlyList<Symbol> ChildSymbols => throw new NotImplementedException();
        }

        public abstract class Operand : NonTerminalSymbol
        {
            protected Operand(OperandType type, params Symbol[] childs)
            {
                OperandType = type;
                this.childs = childs;
            }

            public OperandType OperandType { get; }

            public override sealed Enum SymbolIdentifier => NonTerminalType.Operand;

            public sealed override Enum SymbolSubidentifier => OperandType;

            private readonly Symbol[] childs;

            public override IReadOnlyList<Symbol> ChildSymbols => childs;

            public override string ToString()
            {
                return base.ToString() + " ";
            }
        }

        public class ImmediateOperand : Operand
        {
            public ImmediateOperand(IntegerToken integer)
                : base(OperandType.Immediate, integer)
            {
            }

            public IntegerToken Integer { get; }

            public ulong Data { get => Integer.UnsignedValue; }
        }

        public class RegisterOperand : Operand
        {
            public RegisterOperand(RegisterToken register)
                : base(OperandType.Register, register)
            {
            }

            public RegisterToken Register { get; }
        }

        public class MemoryImmediate : Operand
        {
            public MemoryImmediate(
                OperatorToken leftBracket,
                IntegerToken immediateAddress,
                OperatorToken rightBracket)
                : base(
                      OperandType.MemoryImmediate,
                      leftBracket,
                      immediateAddress,
                      rightBracket)
            {
                ImmediateAddress = immediateAddress;
            }

            public IntegerToken ImmediateAddress { get; }
            public ulong Address { get => ImmediateAddress.UnsignedValue; }
        }

        public class IndirectOperand : Operand
        {
            public IndirectOperand(RegisterToken register)
                : base(OperandType.Indirect, register)
            {
                Register = register;
            }

            public RegisterToken Register { get; }
        }

        public class LocalOperand : Operand
        {
            public LocalOperand(
                OperatorToken localOp,
                OperatorToken leftSquareBracket,
                IntegerToken offset,
                OperatorToken rightSquareBracket)
                : base(
                      OperandType.Local,
                      localOp,
                      leftSquareBracket,
                      offset,
                      rightSquareBracket)
            {
                OffsetToken = offset;
            }

            public IntegerToken OffsetToken { get; }
            public ulong Value { get => OffsetToken.UnsignedValue; }
        }

        public class BaseOperandWithImmediateOffset : Operand
        {
            public BaseOperandWithImmediateOffset(
                OperatorToken leftSquareBracket,
                Token registerOrOffset1,
                OperatorToken plus,
                Token registerOrOffset2,
                OperatorToken rightSquareBracket)
                : base(OperandType.BaseWithImmediateOffset,
                      leftSquareBracket,
                      registerOrOffset1,
                      plus,
                      registerOrOffset2,
                      rightSquareBracket)
            {
                static void Throw(Token tok, string paramName)
                {
                    throw new InvalidOperationException($"Wrong {paramName} type: {tok.GetType().FullName}");
                }

                if (registerOrOffset2 is RegisterToken reg)
                {
                    /*Register = reg;
                    Offset = registerOrOffset2 as IntegerToken;
                    */
                    registerOrOffset2 = registerOrOffset1;
                    registerOrOffset1 = reg;
                }
                Register = registerOrOffset1 as RegisterToken;
                if (Register == null)
                {
                    Throw(registerOrOffset1, nameof(registerOrOffset1));
                }
                Offset = registerOrOffset2 as IntegerToken;
                if (Offset == null)
                {
                    Throw(registerOrOffset2, nameof(registerOrOffset2));
                }
            }

            public RegisterToken Register { get; }
            public IntegerToken Offset { get; }
        }

        public class BaseOperandWithRegisterOffset : Operand
        {
            public BaseOperandWithRegisterOffset(
                OperatorToken leftSquareBracket,
                RegisterToken register1,
                OperatorToken signOperator,
                RegisterToken register2,
                OperatorToken rightSquareBracket)
                : base(signOperator.OperatorType == OperatorType.Minus ? OperandType.BaseWithRegisterOffsetDif : OperandType.BaseWithRegisterOffsetSum,
                      leftSquareBracket,
                      register1,
                      signOperator,
                      register2,
                      rightSquareBracket)
            {
                Register1 = register1;
                Register2 = register2;
                OffsetSign = signOperator.OperatorType switch
                {
                    OperatorType.Plus => OffsetSign.Plus,
                    OperatorType.Minus => OffsetSign.Minus,
                    _ => throw new InvalidOperationException($"Invalid sign: {signOperator.Text}"),
                };
            }

            public OffsetSign OffsetSign { get; }

            public RegisterToken Register1 { get; }
            public RegisterToken Register2 { get; }
        }

        public class RelativeOperand : Operand
        {
            public RelativeOperand(
                OperatorToken tild,
                IntegerToken offset)
                : base(OperandType.Relative,
                      tild,
                      offset)
            {
                OffsetToken = offset;
            }

            public IntegerToken OffsetToken { get; }
            public long Value { get => OffsetToken.SignedValue; }
        }

        public class IdentifierOperand : Operand
        {
            public IdentifierOperand(IdentifierToken identifier)
                : base(OperandType.Identifier,
                      identifier)
            {
                Identifier = identifier;
            }

            public IdentifierToken Identifier { get; }
            public string Name { get => Identifier.Text; }
        }

        public class Offset : Operand
        {
            public Offset(OperatorToken offsetOp, IdentifierToken id)
                : base(OperandType.IdentifierOffset,
                      offsetOp,
                      id)
            {
                Identifier = id;
            }

            public IdentifierToken Identifier { get; }
            public string Name { get => Identifier.Text; }
        }

        public class Instruction : NonTerminalSymbol
        {
            public Instruction(IdentifierToken label, OperatorToken colon, LinkedListNode<Symbol> mnemonicNode)
                : this(mnemonicNode)
            {
                var oldList = childSymbols;
                childSymbols = new List<Symbol>
                {
                    label,
                    colon
                };
                childSymbols.AddRange(oldList);
                Label = label;
            }

            public Instruction(LinkedListNode<Symbol> mnemonicNode)
            {
                var curNode = mnemonicNode;
                var curVal = curNode.Value;

                void Advance()
                {
                    childSymbols.Add(curVal);
                    curNode = curNode.Next;
                    curVal = curNode.Value;
                }

                InstructionType = InstructionType.Unconditional;

                if (curVal is IdentifierToken l)
                {
                    Label = l;
                    Advance();
                    if (!(curVal is OperatorToken c && c.OperatorType == OperatorType.Colon))
                    {
                        throw new InvalidOperationException("Invalid label tokens: there's no colon");
                    }
                    Advance();
                }

                Mnemonic = (MnemonicToken)curVal;
                Advance();
                // Спецификаторы инструкции
                while (curVal.GetType() == typeof(InstructionTypeSpecifier))
                {
                    Specifiers.Add((InstructionTypeSpecifier)curVal);
                    Advance();
                }
                // операнды
                while (curVal is Operand op)
                {
                    Operands.Add(op);
                    Advance();
                    // Если запятая
                    if (curVal is OperatorToken tok && tok.OperatorType == OperatorType.Comma)
                    {
                        Advance();
                    }
                }
                if (curVal is InstructionConditionSpecifier cond)
                {
                    Condition = cond;
                    Advance();
                    Advance(); // запятая после условия
                    if (curVal is RegisterOperand reg)
                    {
                        InstructionType = InstructionType.ConditionalWrite;
                        ConditionalWriteRegister = reg;
                    }
                    else if (curVal is Operand trueBranch)
                    {
                        InstructionType = InstructionType.ConditionalBranch;
                        TrueBranch = trueBranch;
                        Advance();
                        if (curVal is OperatorToken comma && comma.OperatorType == OperatorType.Comma)
                        {
                            Advance();
                            FalseBranch = (Operand)curVal;
                        }
                    }
                }
            }

            /// <summary>
            /// Может быть null
            /// </summary>
            public IdentifierToken Label { get; }
            public MnemonicToken Mnemonic { get; }
            public IList<InstructionTypeSpecifier> Specifiers { get; } = new List<InstructionTypeSpecifier>();
            public IList<Operand> Operands { get; } = new List<Operand>();

            public InstructionConditionSpecifier Condition { get; }
            public Operand TrueBranch { get; }
            public Operand FalseBranch { get; }
            public RegisterOperand ConditionalWriteRegister { get; }

            private readonly List<Symbol> childSymbols = new List<Symbol>();
            public override IReadOnlyList<Symbol> ChildSymbols => childSymbols;

            public override Enum SymbolIdentifier => NonTerminalType.Instruction;

            public InstructionType InstructionType { get; }
            public override Enum SymbolSubidentifier { get => InstructionType; }
        }

        public class DataDefinition : NonTerminalSymbol
        {
            public DataDefinition(
                LinkedListNode<Symbol> directiveStart)
            {
                LinkedListNode<Symbol> curNode = directiveStart;
                Symbol curVal = curNode.Value;

                void Advance()
                {
                    childSymbols.Add(curVal);
                    curNode = curNode.Next;
                    curVal = curNode.Value;
                }

                var dir = (DirectiveToken)curVal;
                DataWidth = dir.DirectiveType switch
                {
                    DirectiveType.Data8 => DataWidth.Byte,
                    DirectiveType.Data16 => DataWidth.Word,
                    DirectiveType.Data32 => DataWidth.Dword,
                    DirectiveType.Data64 => DataWidth.Qword,
                    _ => throw new InvalidOperationException("Invalid directive type: " + dir.DirectiveType),
                };
                Advance();
                if (curVal.SymbolIdentifier.Equals(TokenType.Identifier))
                {
                    // Значит, есть идентификатор
                    Name = ((IdentifierToken)curVal).Text;
                    Advance();
                }
                // Добавление элементов данных
                while (curVal is IntegerToken || curVal is StringToken)
                {
                    Data.Add(curVal);
                    Advance();
                    if (curVal.SymbolSubidentifier.Equals(OperatorType.Comma))
                    {
                        // Также пропустить запятую
                        Advance();
                    }
                }
            }

            public DataWidth DataWidth { get; }

            public string Name { get; }
            public IList<Symbol> Data { get; } = new List<Symbol>();

            public override Enum SymbolIdentifier => NonTerminalType.DataDefinition;

            public override Enum SymbolSubidentifier => DataWidth;

            private readonly List<Symbol> childSymbols = new List<Symbol>();
            public override IReadOnlyList<Symbol> ChildSymbols => childSymbols;
        }

        public class Procedure : NonTerminalSymbol
        {
            public Procedure(
                LinkedListNode<Symbol> start)
            {
                LinkedListNode<Symbol> curNode = start;
                Symbol curVal = curNode.Value;

                void Advance()
                {
                    childSymbols.Add(curVal);
                    curNode = curNode.Next;
                    curVal = curNode.Value;
                }

                Advance(); // Директива .proc
                Name = ((IdentifierToken)curVal).Text;
                Advance(); // Оператор {
                while (
                    curVal.SymbolIdentifier.Equals(NonTerminalType.Instruction)
                    || curVal.SymbolIdentifier.Equals(NonTerminalType.DataDefinition))
                {
                    Advance();
                }
                // Теперь последний символ должен быть }
                if (!curVal.SymbolSubidentifier.Equals(OperatorType.RightCurlyBrace))
                {
                    throw new SyntaxAnalizerException(curVal, "Ожидалось \"}\"");
                }
                Advance();
            }

            public string Name { get; }

            private readonly List<Symbol> childSymbols = new List<Symbol>();
            public override IReadOnlyList<Symbol> ChildSymbols { get; }
            public override Enum SymbolIdentifier => NonTerminalType.Proc;
            public override Enum SymbolSubidentifier => null;
        }

        public class AsmFile : NonTerminalSymbol
        {
            public AsmFile(LinkedListNode<Symbol> symbol)
            {
                LinkedListNode<Symbol> currentSymbol = symbol;
                while (currentSymbol != null)
                {
                    Enum id = currentSymbol.Value.SymbolIdentifier;
                    switch (id)
                    {
                        case NonTerminalType.BitnessDirectives:
                        case NonTerminalType.DataDefinition:
                        case NonTerminalType.EndiannessDirectives:
                        case NonTerminalType.Instruction:
                        case NonTerminalType.Proc:
                            childSymbols.Add(currentSymbol.Value);
                            break;
                        default:
                            throw new SyntaxAnalizerException(currentSymbol.Value, "Wrong symbol type for AsmFile symbol: " + id);
                    }
                    currentSymbol = currentSymbol.Next;
                }
            }

            public override Enum SymbolIdentifier => NonTerminalType.AsmFile;

            public override Enum SymbolSubidentifier => null;

            private readonly List<Symbol> childSymbols = new List<Symbol>();
            public override IReadOnlyList<Symbol> ChildSymbols => childSymbols;
        }

        public enum RuleAction
        {
            /// <summary>
            /// Для символов, которые не раскладываются на поддеревья
            /// </summary>
            Nothing,
            /// <summary>
            /// Это значит, что надо "прошагать" по символам,
            /// нельзя заменять текущий символ
            /// </summary>
            Matched,
            /// <summary>
            /// Это значит, что надо заменить текущий символ, а потом "шагнуть" вперёд
            /// </summary>
            Collapsed,
        }

        public interface ISymbolRule
        {
            /// <summary>
            /// Обязательное условие: в метод передаётся новый пустой стек, являющийся дочерним для другого стека
            /// </summary>
            /// <param name="symbolNode"></param>
            /// <param name="backup"></param>
            /// <returns></returns>
            bool TryCollapse(LinkedListNode<Symbol> symbolNode, out RuleAction action, IList backup, out int matchedCount);
        }

        public static class SymbolRules
        {
            public static ISymbolRule Empty { get; } = SymbolMatcher.EmptyMatcher;
        }

        // Класс для сопоставления символов правилу
        public abstract class SymbolMatcher : ISymbolRule
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="list"></param>
            /// <param name="index"></param>
            /// <returns>Количество символов, соответствующих правилу</returns>
            public abstract (bool, int) Matches(LinkedListNode<Symbol> symbol);

            public static SymbolMatcher CreateSimpleMatcher<T>(
                SymbolType? st,
                Enum symbolIdentifier = null,
                Enum symbolSubidentifier = null,
                Func<T, bool> matchFunc = null)
                where T : Symbol
            {
                return new SingleSymbolMatcher<T>(
                    st,
                    symbolIdentifier,
                    symbolSubidentifier,
                    matchFunc);
            }

            public static SymbolMatcher CreateAdvancedMatcher(Func<LinkedListNode<Symbol>, (bool, int)> matchFunction)
            {
                return new ComplexSingleSymbolMatcher(matchFunction);
            }

            public bool TryCollapse(LinkedListNode<Symbol> symbolNode, out RuleAction action, IList _, out int matchedCount)
            {
                action = RuleAction.Matched;
                (bool matches, int matchedCountTmp) = Matches(symbolNode);
                matchedCount = matchedCountTmp;
                // Игнорируем стек. Это значит, что мы ничего не сворачивали,
                // и переданный стек остаётся пустым
                return matches;
            }

            public static SymbolMatcher EmptyMatcher { get; } = new EmptyMatcher();
        }

        public class EmptyMatcher : SymbolMatcher
        {
            public override (bool, int) Matches(LinkedListNode<Symbol> symbol)
            {
                return (true, 0);
            }
        }

        public class SingleSymbolMatcher<T> : SymbolMatcher
            where T : Symbol
        {
            public SingleSymbolMatcher(
                SymbolType? st = null,
                Enum symbolIdentifier = null,
                Enum symbolSubidentifier = null,
                Func<T, bool> matchFunc = null)
            {
                MatchFunc = matchFunc;
                SymbolType = st;
                SymbolIdentifier = symbolIdentifier;
                SymbolSubIdentifier = symbolSubidentifier;
            }

            public sealed override (bool, int) Matches(LinkedListNode<Symbol> symbolNode)
            {
                SyntaxAnalyzer.Level++;
                try
                {
                    StringBuilder spaces = new StringBuilder();
                    for (int i = 0; i < SyntaxAnalyzer.Level; i++)
                    {
                        spaces.Append('|');
                    }
                    Console.Write($"{spaces}Matching symbol {symbolNode.Value}: ");
                    Symbol symbol = symbolNode.Value;
                    if (!symbol.GetType().IsSubclassOf(typeof(T)) && symbol.GetType() != typeof(T))
                    {
                        Console.WriteLine("fault");
                        return (false, 0);
                    }
                    if (SymbolType != null)
                    {
                        if (symbol.SymbolType != SymbolType.Value)
                        {
                            Console.WriteLine("fault");
                            return (false, 0);
                        }
                    }
                    if (SymbolIdentifier != null)
                    {
                        if (!symbol.SymbolIdentifier.Equals(SymbolIdentifier))
                        {
                            Console.WriteLine("fault");
                            return (false, 0);
                        }
                    }
                    if (SymbolSubIdentifier != null)
                    {
                        if (!symbol.SymbolSubidentifier.Equals(SymbolSubIdentifier))
                        {
                            Console.WriteLine("fault");
                            return (false, 0);
                        }
                    }
                    if (MatchFunc != null)
                    {
                        bool success = MatchFunc((T)symbol);
                        if (success)
                        {
                            Console.WriteLine("success");
                        }
                        else
                        {
                            Console.WriteLine("fault");
                        }
                        return (success, 1);
                    }
                    Console.WriteLine("success");
                    return (true, 1);
                }
                finally
                {
                    SyntaxAnalyzer.Level--;
                }
            }

            public Func<T, bool> MatchFunc { get; }
            public SymbolType? SymbolType { get; }
            public Enum SymbolIdentifier { get; }
            public Enum SymbolSubIdentifier { get; }
        }

        public class ComplexSingleSymbolMatcher : SymbolMatcher
        {
            public ComplexSingleSymbolMatcher(Func<LinkedListNode<Symbol>, (bool, int)> matchFunc)
            {
                MatchFunction = matchFunc ?? throw new ArgumentNullException(nameof(matchFunc));
            }

            public Func<LinkedListNode<Symbol>, (bool, int)> MatchFunction { get; }

            public override (bool, int) Matches(LinkedListNode<Symbol> symbolNode)
            {
                SyntaxAnalyzer.Level++;
                try
                {
                    StringBuilder spaces = new StringBuilder();
                    for (int i = 0; i < SyntaxAnalyzer.Level; i++)
                    {
                        spaces.Append('|');
                    }
                    Console.Write($"{spaces}Matching symbol {symbolNode.Value}: ");
                    var (success, matchCount) = MatchFunction(symbolNode);
                    if (success)
                    {
                        Console.WriteLine(" success");
                        return (true, matchCount);
                    }
                    else
                    {
                        Console.WriteLine(" fault");
                        return (false, 0);
                    }
                }
                finally
                {
                    SyntaxAnalyzer.Level--;
                }
            }
        }

        public struct NodeWrapper<T>
        {
            public NodeWrapper(LinkedListNode<T> node)
            {
                FirstNode = node;
                cache = new Dictionary<int, LinkedListNode<T>>();
            }

            public LinkedListNode<T> FirstNode { get; }

            public T this[int index] { get => GetNode(index).Value; }

            public LinkedListNode<T> GetNode(int index)
            {
                if (!cache.TryGetValue(index, out var val))
                {
                    var curNode = FirstNode;
                    for (int i = 0; i < index; i++)
                    {
                        curNode = curNode.Next;
                        if (curNode == null)
                        {
                            throw new IndexOutOfRangeException();
                        }
                    }
                    cache.Add(index, curNode);
                    return curNode;
                }
                return val;
            }

            private readonly Dictionary<int, LinkedListNode<T>> cache;
        }

        public class SymbolRuleSequence : ISymbolRule
        {
            public SymbolRuleSequence(IReadOnlyCollection<string> rules)
            {
                Rules = rules;
            }

            public IReadOnlyCollection<string> Rules { get; }

            // стек backups уже выделен
            public bool TryCollapse(LinkedListNode<Symbol> startingSymbol, out RuleAction action, IList backups, out int matchedCount)
            {
                matchedCount = 0;
                action = RuleAction.Matched;
                SyntaxAnalyzer.Level++;
                try
                {
                    LinkedListNode<Symbol> currentNode = startingSymbol;
                    LinkedListNode<Symbol> prevStartingSymbol = startingSymbol.Previous;
                    LinkedList<Symbol> symbolStream = startingSymbol.List;
                    LinkedListNode<Symbol> previousSymbol = startingSymbol.Previous; //Символ до последовательности, которую сворачиваем
                    // Вся последовательность правил должна выполниться
                    foreach (var ruleName in Rules)
                    {
                        if (currentNode == null)
                        {
                            throw new SyntaxAnalizerException("Current node is null, rule: " + ruleName);
                        }
                        SyntaxAnalyzer.LastRule = ruleName;
                        StringBuilder spaces = new StringBuilder();
                        for (int i = 0; i < SyntaxAnalyzer.Level; i++)
                        {
                            spaces.Append('|');
                        }
                        Console.WriteLine($"{spaces}{nameof(SymbolRuleSequence)}: Trying rule: {ruleName}, current symbol: {currentNode.Value}");
                        if (!SymbolRuleStore.Symbols.TryGetValue(ruleName, out var rule))
                        {
                            throw new InvalidOperationException("Rule not registered: " + ruleName);
                        }
                        // LinkedListNode<Symbol> oldSymbol = currentNode;
                        IList innerBackups = new ArrayList();
                        bool success = rule.TryCollapse(currentNode, out var innerAction, innerBackups, out int innerMatchedCount);
                        currentNode = previousSymbol?.Next ?? symbolStream.First; // Восстанавливаем позицию в списке
                        // Получаем символ, который вставлен на месте прежнего набора символов
                        if (!success)
                        {
                            // Необходимо сдвинуть узел назад, так как в прошлый раз не было бекапа,
                            // ведь свёртка неуспешна
                            //currentNode = currentNode.Previous;
                            Console.WriteLine(spaces.ToString() + "fault");
                            // Восстанавливаем состояние списка до свёртки
                            // Используем именно текущий бэкап, т.к. ранее мы добавляли в него узлы на предыдущих итерациях
                            // Если мы всё же не добавляли, то ничего не произойдёт, т.к. backups будет пустым
                            startingSymbol = prevStartingSymbol?.Next ?? symbolStream.First;
                            symbolStream.Unwind(startingSymbol, action, backups);
                            return false;
                        }
                        matchedCount += innerMatchedCount;
                        if (innerMatchedCount > 0)
                        {
                            backups.Add((currentNode, innerAction, innerBackups));
                        }
                        Console.WriteLine(spaces.ToString() + $"success, collapsed symbol: {currentNode.Value}");
                        // Если последнее правило было пустым, то нельзя сдвигаться на символ вперёд
                        //if (SyntaxAnalyzer.LastRule != SymbolRuleStore.EMPTY_RULE_NAME)
                        {
                            for (int i = 0; i < innerMatchedCount; i++)
                            {
                                currentNode = currentNode.Next;
                            }
                            previousSymbol = currentNode.Previous;
                        }
                    }
                    return true;
                }
                finally
                {
                    SyntaxAnalyzer.Level--;
                }
            }
        }

        public delegate (Symbol collapsedSymbol, LinkedListNode<Symbol> end) CollapseSymbol(NodeWrapper<Symbol> start);

        public class SymbolRule : ISymbolRule
        {
            public SymbolRule(
                IReadOnlyCollection<(string ruleName, CollapseSymbol createSymbol)> rulesAndCollapsers)
            {
                RulesAndCollapsers = rulesAndCollapsers;
            }

            // Объекты-редукции, если выполняется одна из них, значит, символ соответствует внутренней редукции
            public IReadOnlyCollection<(string ruleName, CollapseSymbol)> RulesAndCollapsers { get; }

            public bool TryCollapse(LinkedListNode<Symbol> startingSymbol, out RuleAction action, IList backups, out int matchedCount)
            {
                matchedCount = 0;
                action = RuleAction.Collapsed;
                SyntaxAnalyzer.Level++;
                try
                {
                    LinkedList<Symbol> list = startingSymbol.List;
                    LinkedListNode<Symbol> currentSymbol = startingSymbol;
                    LinkedListNode<Symbol> prevNode = startingSymbol.Previous;
                    // Сначала произведём редукцию по внутренним правилам
                    // Только одно из правил должно выполниться
                    foreach ((var ruleName, var collapser) in RulesAndCollapsers)
                    {
                        SyntaxAnalyzer.LastRule = ruleName;
                        StringBuilder spaces = new StringBuilder();
                        for (int i = 0; i < SyntaxAnalyzer.Level; i++)
                        {
                            spaces.Append('|');
                        }
                        Console.WriteLine($"{spaces}{nameof(SymbolRule)}: Trying rule: {ruleName}, current symbol: {currentSymbol.Value}");
                        if (!SymbolRuleStore.Symbols.TryGetValue(ruleName, out var rule))
                        {
                            throw new InvalidOperationException("Rule is not registered: " + ruleName);
                        }
                        // Пробуем свернуть узлы по внутреннему правилу
                        IList innerBackups = new ArrayList();
                        //var oldNode = symbolNode;
                        bool success = rule.TryCollapse(currentSymbol, out var innerAction, innerBackups, out int innerMatchedCount);
                        // Теперь в стеке свёрнутые узлы
                        //LinkedListNode<Symbol> oldSymbol = symbolNode; // Символ до вызова collapser()
                        // Восстанавливаем позицию текущего символа (перемещаем её на первый замещающий)
                        currentSymbol = prevNode?.Next ?? list.First;
                        if (success)
                        {
                            matchedCount = innerMatchedCount; // Сначала matched столько же, сколько у внутреннего правила
                            if (innerMatchedCount == 0)
                            {
                                return true;
                            }
                            IList thisBackups = new ArrayList();
                            //backups.Push((oldSymbol, innerBackups));
                            // Если это удалось, создаём символ на основе свёрнутых символов
                            (Symbol collapsedSymbol, LinkedListNode<Symbol> end) = collapser(new NodeWrapper<Symbol>(currentSymbol));
                            list.MoveAndReplaceListRange(currentSymbol, end, new LinkedListNode<Symbol>(collapsedSymbol), out var collapsedSymbols);
                            matchedCount -= collapsedSymbols.Count - 1; // После сворачивания впереди могло остаться сколько-то символов.
                            // Обычно количество свёрнутых символов равно matched. Добавляем 1, т.к. хотя бы один символ всё же точно добавится
                            //symbolNode = prevNode?.Next ?? list.First;
                            Console.WriteLine($"{spaces}success, collapsed symbol: {collapsedSymbol}");
                            //backups.Add((collapsedSymbols.First, RuleAction.Collapsed, symbolNode));
                            backups.Add((collapsedSymbols.First, innerAction, innerBackups));
                            collapsedSymbols.RemoveFirst();
                            while (collapsedSymbols.First != null)
                            {
                                backups.Add((collapsedSymbols.First, RuleAction.Nothing, (IList)null));
                                collapsedSymbols.RemoveFirst();
                            }
                            return true;
                        }
                        else
                        {
                            //LinkedListNode<Symbol> prev = symbolNode.Previous;
                            //list.Unwind(currentSymbol, innerAction, innerBackups);
                            currentSymbol = prevNode?.Next ?? list.First;
                        }
                    }
                    return false;
                }
                finally
                {
                    SyntaxAnalyzer.Level--;
                }
            }
        }

        public static partial class SymbolRuleStore
        {
            internal static void CollapseSymbols(LinkedList<Symbol> symbolStream)
            {
                if (!Symbols.TryGetValue(ROOT_RULE_NAME, out var rule))
                {
                    throw new InvalidOperationException("No root symbol: " + ROOT_RULE_NAME);
                }
                IList backups = new ArrayList();
                if (!rule.TryCollapse(symbolStream.First, out var action, backups, out int matched))
                {
                    throw new InvalidOperationException("Error while collapsing symbols...");
                }
            }

            internal const string ROOT_RULE_NAME = "asm_file";
            internal const string EMPTY_RULE_NAME = "";

            public static IDictionary<string, ISymbolRule> Symbols { get; } = new Dictionary<string, ISymbolRule>();
        }

        public static class LinkedListExtensions
        {
            public static void MoveAndReplaceListRange<T>(
                this LinkedList<T> list,
                LinkedListNode<T> first,
                LinkedListNode<T> last,
                LinkedListNode<T> replaceNode,
                out LinkedList<T> listWithMovedNodes)
            {
                listWithMovedNodes = new LinkedList<T>();
                while (first != last)
                {
                    LinkedListNode<T> next = first.Next;
                    list.Remove(first);
                    listWithMovedNodes.AddLast(first);
                    first = next;
                }
                // Теперь остался один узел
                list.AddAfter(last, replaceNode);
                list.Remove(last);
                listWithMovedNodes.AddLast(last);
            }

            /// <summary>
            /// 
            /// </summary>
            /// <typeparam name="T"></typeparam>
            /// <param name="list"></param>
            /// <param name="node"></param>
            /// <param name="other"></param>
            /// <returns>Возвращает первый узел, который оказывается вместо заменённого</returns>
            public static LinkedListNode<T> ReplaceSingleNode<T>(
                this LinkedList<T> list,
                LinkedListNode<T> node,
                IList<LinkedListNode<T>> other)
            {
                if (other.Count == 0)
                {
                    return node;
                }
                else if (other.Count == 1 && node == other[0])
                {
                    return node;
                }
                foreach (var replacingNode in other)
                {
                    list.AddAfter(node, replacingNode);
                }
                // Добавлены все узлы. Осталось удалить узел, который мы заменяем
                var ret = node.Next;
                list.Remove(node);
                return ret;
            }

            public static void Append<T>(
                this LinkedList<T> list,
                IEnumerable<T> collection)
            {
                foreach (var v in collection)
                {
                    list.AddLast(v);
                }
            }

            // Функция рекурсивно заменяет текущий узел списком узлов из стека
            public static void Unwind(this LinkedList<Symbol> list, LinkedListNode<Symbol> oldNode, RuleAction currentStatus, IList backups)
            {
                var next = oldNode.Next;

                void InsertSymbol(LinkedListNode<Symbol> insertionNode)
                {
                    if (next == null)
                    {
                        list.AddLast(insertionNode);
                    }
                    else
                    {
                        //if (next.Previous != insertionNode)
                        {
                            try
                            {
                                list.AddBefore(next, insertionNode);
                            }
                            catch (Exception e)
                            {
                                ;
                                throw;
                            }
                        }
                    }
                }

                LinkedListNode<Symbol> currentNode = oldNode;

                if (currentStatus == RuleAction.Collapsed)
                {
                    list.Remove(oldNode);
                    // Сначала нужно развернуть свёрнутые узлы
                    foreach (object obj in backups)
                    {
                        var (insertionNode, _, _) = ((LinkedListNode<Symbol>, RuleAction, IList))obj;
                        InsertSymbol(insertionNode);
                    }
                }
                if (next != null && next.Previous != null)
                {
                    currentNode = next.Previous;
                }
                else
                {
                    currentNode = list.Last;
                }
                if (backups == null)
                {
                    return;
                }
                foreach (object obj in backups)
                {
                    next = currentNode.Next;
                    // Теперь обрабатываем каждый узел
                    var (insertionNode, nodeStatus, innerBackups) = ((LinkedListNode<Symbol>, RuleAction, IList))obj;
                    // Продолжить раскрутку, а потом перейти к следующему символу
                    Unwind(list, currentNode, nodeStatus, innerBackups);
                    currentNode = next?.Previous ?? list.Last;
                    currentNode = currentNode.Next;
                }
            }
        }
    }
}
