using Microsoft.VisualBasic.CompilerServices;
using PulsarAssembler.Tokens;
using System;
using System.Collections.Generic;
using System.Data;

namespace PulsarAssembler.Syntax
{

    /// Класс SymbolRule сворачивает символы по дочерним правилам и дополнительно
    /// самостоятельно проводит свёртку символов,
    /// класс SymbolRuleSequence проводит свёртку символов только благодаря дочерним правилам
    /// 

    /*internal class SymbolRuleListBuilder
    {
        public List<ISymbolRule> List { get; } = new List<ISymbolRule>();

        public SymbolRuleListBuilder AddSimpleMatcher<T>(
            SymbolType? st = null,
            Enum symbolIdentifier = null,
            Enum symbolSubidentifier = null,
            Func<T, bool> matchFunc = null)
            where T : Symbol
        {
            List.Add(SymbolMatcher.CreateSimpleMatcher<T>(
                st,
                symbolIdentifier,
                symbolSubidentifier,
                matchFunc));
            return this;
        }

        public SymbolRuleListBuilder AddAdvancedMatcher(Func<LinkedListNode<Symbol>, bool> matchFunction)
        {
            List.Add(SymbolMatcher.CreateAdvancedMatcher(matchFunction));
            return this;
        }

        public SymbolRuleListBuilder AddSymbolRuleSequence(IReadOnlyCollection<string> rules)
        {
            List.Add(new SymbolRuleSequence(rules));
            return this;
        }

        public SymbolRuleListBuilder AddSymbolRule(
            IReadOnlyCollection<(string, CollapseSymbol)> rulesAndCollapsers)
        {
            List.Add(new SymbolRule(rulesAndCollapsers));
            return null;
        }

        public SymbolRuleListBuilder AddSymbolRule(
            params (string, CollapseSymbol)[] rulesAndCollapsers)
        {
            List.Add(new SymbolRule(rulesAndCollapsers));
            return this;
        }

        public SymbolRuleListBuilder AddEmptyRule()
        {
            List.Add(SymbolRules.Empty);
            return this;
        }
    }*/

    internal class SymbolRuleStoreBuilder
    {
        public IDictionary<string, ISymbolRule> Dictionary { get; } = new Dictionary<string, ISymbolRule>();

        /// <summary>
        /// Добавляет правило, проверяющее текущий символ на соответствие типа и других условий
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="name"></param>
        /// <param name="st"></param>
        /// <param name="symbolIdentifier"></param>
        /// <param name="symbolSubidentifier"></param>
        /// <param name="matchFunc"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddSimpleMatcher<T>(
            string name,
            SymbolType? st = null,
            Enum symbolIdentifier = null,
            Enum symbolSubidentifier = null,
            Func<T, bool> matchFunc = null)
            where T : Symbol
        {
            Dictionary.Add(name, SymbolMatcher.CreateSimpleMatcher(
                st,
                symbolIdentifier,
                symbolSubidentifier,
                matchFunc));
            return this;
        }

        /// <summary>
        /// Добавляет правило, проверяющее последовательность символов на соответствие с помощью предикатной функции
        /// </summary>
        /// <param name="name"></param>
        /// <param name="matchFunction"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddAdvancedMatcher(string name, Func<LinkedListNode<Symbol>, (bool, int)> matchFunction)
        {
            Dictionary.Add(name, SymbolMatcher.CreateAdvancedMatcher(matchFunction));
            return this;
        }

        /// <summary>
        /// Добавление правила, сворачивающего символы по единственному правилу,
        /// состоящему из последовательности символов
        /// </summary>
        /// <param name="name"></param>
        /// <param name="rules"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddNonCollapsingSymbolRule(string name, IReadOnlyCollection<string> rules)
        {
            Dictionary.Add(name, new SymbolRuleSequence(rules));
            return this;
        }

        /// <summary>
        /// Добавление правила, сворачивающего символы по единственному правилу,
        /// состоящему из последовательности символов
        /// </summary>
        /// <param name="name"></param>
        /// <param name="rules"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddNonCollapsingSymbolRule(string name, string[] rules)
        {
            AddNonCollapsingSymbolRule(name, (IReadOnlyCollection<string>)rules);
            return this;
        }

        /// <summary>
        /// Добавление правила, сворачивающего символы по нескольким правилам,
        /// каждое из которых состоит из нескольких правил
        /// </summary>
        /// <param name="name"></param>
        /// <param name="rules"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddCollapsingSymbolRule(
            string name,
            params (string[] ruleList, CollapseSymbol collapseFunc)[] rules)
        {
            List<(string, CollapseSymbol)> listForSymbolRule = new List<(string, CollapseSymbol)>();
            for (int i = 0; i < rules.Length; i++)
            {
                var (ruleList, collapseFunc) = rules[i];
                string tmpRuleName = string.Format("{0}#{1}", name, i);
                AddNonCollapsingSymbolRule(tmpRuleName, ruleList);
                listForSymbolRule.Add((tmpRuleName, collapseFunc));
            }
            AddCollapsingSymbolRule(name, listForSymbolRule);
            return this;
        }

        /// <summary>
        /// Добавление правила, просто проверяющего на соответствие нескольким правилам
        /// последовательности символов
        /// </summary>
        /// <param name="name"></param>
        /// <param name="ruleLists"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddNonCollapsingSymbolRule(
            string name,
            params string[][] ruleLists)
        {
            List<string> symbolList = new List<string>();
            for (int i = 0; i < ruleLists.Length; i++)
            {
                var ruleList = ruleLists[i];
                string tmpRuleName = string.Format("{0}#{1}", name, i);
                AddNonCollapsingSymbolRule(tmpRuleName, ruleList);
                symbolList.Add(tmpRuleName);
            }
            List<(string, CollapseSymbol)> rulesAndCollapsers = new List<(string, CollapseSymbol)>();
            foreach (string rule in symbolList)
            {
                // "Костыль", чтобы объект класса коллапсирующего правила стал неколлапсирующим
                // TODO: переписать классы правил
                rulesAndCollapsers.Add((rule, (NodeWrapper<Symbol> node) => (node[0], node.GetNode(0))));
            }
            AddCollapsingSymbolRule(name, rulesAndCollapsers);
            return this;
        }

        /// <summary>
        /// Добавление правила, преобразующего символ в другой
        /// </summary>
        /// <param name="name"></param>
        /// <param name="rulesAndCollapsers"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddCollapsingSymbolRule(
            string name,
            IReadOnlyCollection<(string, CollapseSymbol)> rulesAndCollapsers)
        {
            Dictionary.Add(name, new SymbolRule(rulesAndCollapsers));
            return null;
        }

        /// <summary>
        /// Добавление правила, преобразующего символ в другой
        /// </summary>
        /// <param name="name"></param>
        /// <param name="rulesAndCollapsers"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddCollapsingSymbolRule(
            string name,
            params (string, CollapseSymbol)[] rulesAndCollapsers)
        {
            Dictionary.Add(name, new SymbolRule(rulesAndCollapsers));
            return this;
        }

        /// <summary>
        /// Добавление пустого правила
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public SymbolRuleStoreBuilder AddEmptyRule(string name)
        {
            Dictionary.Add(name, SymbolRules.Empty);
            return this;
        }
    }

    public static partial class SymbolRuleStore
    {
        static SymbolRuleStore()
        {
            SymbolRuleStoreBuilder storeBuilder = new SymbolRuleStoreBuilder();

            storeBuilder.AddEmptyRule(EMPTY_RULE_NAME);

            storeBuilder.AddSimpleMatcher<MnemonicToken>(
                "mnemonic",
                SymbolType.Terminal,
                TokenType.Mnemonic)

                .AddSimpleMatcher<OperatorToken>(
                "-",
                null,
                null,
                OperatorType.Minus)

                .AddSimpleMatcher<OperatorToken>(
                "+",
                null,
                null,
                OperatorType.Minus)

                .AddSimpleMatcher<OperatorToken>(
                "sign",
                null,
                null,
                null,
                op => op.OperatorType == OperatorType.Minus || op.OperatorType == OperatorType.Plus)

                .AddSimpleMatcher<OperatorToken>(
                "[",
                null,
                null,
                OperatorType.LeftSquareBracket)

                .AddSimpleMatcher<OperatorToken>(
                "]",
                null,
                null,
                OperatorType.RightSquareBracket)

                .AddSimpleMatcher<OperatorToken>(
                ",",
                null,
                null,
                OperatorType.Comma)

                .AddSimpleMatcher<OperatorToken>(
                ".",
                null,
                null,
                OperatorType.Dot)

                .AddSimpleMatcher<OperatorToken>(
                "{",
                null,
                null,
                OperatorType.LeftCurlyBrace)

                .AddSimpleMatcher<OperatorToken>(
                "}",
                null,
                null,
                OperatorType.RightCurlyBrace)

                .AddSimpleMatcher<OperatorToken>(
                "~",
                null,
                null,
                OperatorType.Tild)

                .AddSimpleMatcher<OperatorToken>(
                ":",
                null,
                null,
                OperatorType.Colon)

                .AddSimpleMatcher<OperatorToken>(
                "local",
                null,
                null,
                OperatorType.Local)

                .AddSimpleMatcher<OperatorToken>(
                "offset",
                null,
                null,
                OperatorType.Offset)

                .AddSimpleMatcher<DirectiveToken>(
                ".bitness",
                SymbolType.Terminal,
                TokenType.DirectiveName,
                DirectiveType.OperandSize)

                .AddSimpleMatcher<DirectiveToken>(
                ".addresses",
                SymbolType.Terminal,
                TokenType.DirectiveName,
                DirectiveType.AddressSize)

                .AddSimpleMatcher<IntegerToken>("integer")

                .AddCollapsingSymbolRule(
                "bitness_directive",
                (new[] { ".bitness", "integer" }, (NodeWrapper<Symbol> node) => (new BitnessDirectiveSymbol(
                        (DirectiveToken)node[0],
                        (IntegerToken)node[1]),
                        node.GetNode(1))),
                (new[] { ".addresses", "integer" }, (NodeWrapper<Symbol> node) =>
                (new BitnessDirectiveSymbol(
                    (DirectiveToken)node[0],
                    (IntegerToken)node[1]),
                    node.GetNode(1))))

                .AddSimpleMatcher<DirectiveToken>(
                ".littleendian",
                SymbolType.Terminal,
                TokenType.DirectiveName,
                DirectiveType.LittleEndian)

                .AddSimpleMatcher<DirectiveToken>(
                ".bigendian",
                SymbolType.Terminal,
                TokenType.DirectiveName,
                DirectiveType.BigEndian)

                .AddCollapsingSymbolRule(
                "endianness_directive",
                (new[] { ".littleendian", ".bigendian" }, (NodeWrapper<Symbol> node) =>
                (new EndiannessDirective(
                    (DirectiveToken)node[0]),
                    node.GetNode(0))))

                .AddNonCollapsingSymbolRule(
                "directive",
                new string[][]
                {
                    new string[] { "bitness_directive" },
                    new string[] { "endianness_directive" },
                })

                .AddSimpleMatcher<IdentifierToken>(
                "identifier")

                .AddSimpleMatcher<DirectiveToken>(
                "data_type_specifier",
                SymbolType.Terminal,
                TokenType.DirectiveName,
                null,
                spec =>
                spec.DirectiveType >= DirectiveType.Data8 && spec.DirectiveType <= DirectiveType.Data64)

                .AddSimpleMatcher<InstructionTypeSpecifier>(
                "address_type_specifier",
                SymbolType.Terminal,
                TokenType.InstructionSpecifier,
                null,
                spec => (spec.SpecifierType > InstructionTypeSpecifier.A8)
                && (spec.SpecifierType < InstructionTypeSpecifier.A256))

                .AddSimpleMatcher<InstructionTypeSpecifier>(
                ".unaligned",
                SymbolType.Terminal,
                TokenType.InstructionSpecifier,
                InstructionTypeSpecifier.Unaligned)

                .AddSimpleMatcher<InstructionTypeSpecifier>(
                "instruction_specifier")

                .AddSimpleMatcher<InstructionConditionSpecifier>(
                "condition")

                .AddSimpleMatcher<DirectiveToken>(
                ".proc",
                SymbolType.Terminal,
                TokenType.DirectiveName,
                DirectiveType.Proc)

                .AddNonCollapsingSymbolRule(
                "proc",
                new[] { ".proc", "identifier" })

                .AddSimpleMatcher<StringToken>(
                "text_string",
                SymbolType.Terminal,
                TokenType.String)

                .AddAdvancedMatcher(
                "data_definition",
                node => (node.Value.SymbolIdentifier.Equals(TokenType.Integer)
                || node.Value.SymbolIdentifier.Equals(TokenType.String), 1))

                .AddNonCollapsingSymbolRule(
                "data_definition_sequence_inner",
                new string[][] {
                    new string[] { "data_definition", ",", "data_definition_sequence_inner" },
                    new string[] { "data_definition", "," },
                })

                .AddNonCollapsingSymbolRule(
                "data_definition_sequence",
                new string[][] {
                    new string[] { "data_definition_sequence_inner", "data_definition" },
                    new string[] { "data_definition" },
                })

                .AddNonCollapsingSymbolRule(
                "data_identifier",
                new string[][] {
                    new string[] { "identifier" },
                    new string[] { "" },
                })

                .AddCollapsingSymbolRule(
                "data_definition_statement",
                (new string[] { "data_type_specifier", "data_identifier", "data_definition_sequence" },
                (NodeWrapper<Symbol> node) =>
                {
                    var sym = new DataDefinition(node.FirstNode);
                    return (sym, node.GetNode(sym.ChildSymbols.Count - 1));
                }))

                .AddSimpleMatcher<RegisterToken>(
                "gp_register",
                null,
                null,
                RegisterKind.GeneralPurpose)

                .AddSimpleMatcher<RegisterToken>(
                "system_register",
                null,
                null,
                RegisterKind.System)

                .AddSimpleMatcher<RegisterToken>(
                "info_register",
                null,
                null,
                RegisterKind.Informational)

                .AddCollapsingSymbolRule(
                "op_immediate",
                (
                    new[] { "offset", "identifier" },
                    (NodeWrapper<Symbol> node) => (new Offset((OperatorToken)node[0], (IdentifierToken)node[1]), node.GetNode(1))
                ),
                (
                    new[] { "integer" },
                    (NodeWrapper<Symbol> node) => (new ImmediateOperand((IntegerToken)node[0]), node.GetNode(0))
                ));

            CollapseSymbol registerCollapser = (NodeWrapper<Symbol> node) => (new RegisterOperand((RegisterToken)node[0]), node.GetNode(0));
            storeBuilder.AddCollapsingSymbolRule(
                "op_register",
                ("gp_register", registerCollapser),
                ("system_register", registerCollapser),
                ("info_register", registerCollapser))

                .AddCollapsingSymbolRule(
                "op_imm_memory",
                (
                    new string[] { "[", "integer", "]" },
                    (NodeWrapper<Symbol> node) => (new MemoryImmediate((OperatorToken)node[0], (IntegerToken)node[1], (OperatorToken)node[2]), node.GetNode(2))
                ))

                .AddCollapsingSymbolRule(
                "op_indirect",
                (
                    new string[] { "[", "gp_register", "]" },
                    (NodeWrapper<Symbol> node) => (new IndirectOperand((RegisterToken)node[0]), node.GetNode(0))
                ))

                .AddCollapsingSymbolRule(
                "op_local",
                (
                    new string[] { "local", "[", "integer", "]" },
                    (NodeWrapper<Symbol> node) => (new LocalOperand((OperatorToken)node[0], (OperatorToken)node[1], (IntegerToken)node[2], (OperatorToken)node[3]), node.GetNode(3))
                ))

                .AddCollapsingSymbolRule(
                "op_base_w_offset",
                (
                    new string[] { "[", "gp_register", "sign", "integer", "]" },
                    (NodeWrapper<Symbol> node) => (new BaseOperandWithImmediateOffset((OperatorToken)node[0], (Token)node[1], (OperatorToken)node[2], (Token)node[3], (OperatorToken)node[4]), node.GetNode(4))
                ),
                (
                    new string[] { "[", "integer", "sign", "gp_register", "]" },
                    (NodeWrapper<Symbol> node) => (new BaseOperandWithImmediateOffset((OperatorToken)node[0], (Token)node[1], (OperatorToken)node[2], (Token)node[3], (OperatorToken)node[4]), node.GetNode(4))
                ))

                .AddCollapsingSymbolRule(
                "op_base_w_register",
                (
                    new string[] { "[", "gp_register", "sign", "gp_register", "]" },
                    (NodeWrapper<Symbol> node) => (new BaseOperandWithRegisterOffset((OperatorToken)node[0], (RegisterToken)node[1], (OperatorToken)node[2], (RegisterToken)node[3], (OperatorToken)node[4]), node.GetNode(4))
                ))

                .AddCollapsingSymbolRule(
                "op_relative",
                (
                    new string[] { "~", "integer" },
                    (NodeWrapper<Symbol> node) => (new RelativeOperand((OperatorToken)node[0], (IntegerToken)node[1]), node.GetNode(1))
                ))

                .AddCollapsingSymbolRule(
                "op_data",
                (
                    new string[] { "identifier" },
                    (NodeWrapper<Symbol> node) => (new IdentifierOperand((IdentifierToken)node[0]), node.GetNode(0))
                ))

                .AddNonCollapsingSymbolRule(
                "jmp_operand",
                new string[][] {
                    new string[] { "op_imm_memory" },
                    new string[] { "op_indirect" },
                    new string[] { "op_local" },
                    new string[] { "op_base_w_offset" },
                    new string[] { "op_base_w_register" },
                    new string[] { "op_relative" }
                }
                )

                .AddNonCollapsingSymbolRule(
                "st_operand",
                new string[][]
                {
                    new string[] { "op_register" },
                    new string[] { "jmp_operand" },
                    new string[] { "op_data" }
                })

                .AddNonCollapsingSymbolRule(
                "operands",
                new string[][]
                {
                    new string[] { "st_operand", ",", "st_operand", ",", "op_immediate" },
                    new string[] { "st_operand", ",", "st_operand", ",", "st_operand" },
                    new string[] { "st_operand", ",", "op_immediate" },
                    new string[] { "st_operand", ",", "st_operand" },
                    new string[] { "op_immediate" },
                    new string[] { "st_operand" },
                    new string[] { "" },
                })

                .AddNonCollapsingSymbolRule(
                "label",
                new string[][]
                {
                    new string[] { "identifier", ":" },
                    new string[] { "" }
                })

                .AddNonCollapsingSymbolRule(
                "instr_specifier_sequence",
                new string[][]
                {
                    new string[] { "instruction_specifier", "instr_specifier_sequence" },
                    new string[] { "" }
                })

                .AddNonCollapsingSymbolRule(
                "instr_body",
                new string[] { "label", "mnemonic", "instr_specifier_sequence", "operands" })

                .AddNonCollapsingSymbolRule(
                "jump_sequence",
                new string[][]
                {
                    new string[] { "jmp_operand", ",", "jmp_operand" },
                    new string[] { "jmp_operand" },
                })

                .AddNonCollapsingSymbolRule(
                "conditional_body_shared",
                new string[] { "instr_body", ",", "condition" })

                .AddNonCollapsingSymbolRule(
                "conditional_instruction",
                new string[] { "conditional_body_shared", "jump_sequence" })

                .AddNonCollapsingSymbolRule(
                "conditional_cp_instruction",
                new string[] { "conditional_body_shared", "op_register" });

            CollapseSymbol instrCollapser = (NodeWrapper<Symbol> node) =>
            {
                Symbol instr = new Instruction(node.FirstNode);
                return (instr, node.GetNode(instr.ChildSymbols.Count - 1));
            };

            storeBuilder.AddCollapsingSymbolRule(
                "instruction",
                ("conditional_instruction", instrCollapser),
                ("conditional_cp_instruction", instrCollapser),
                ("instr_body", instrCollapser))

                .AddNonCollapsingSymbolRule(
                "proc_element",
                new string[][]
                {
                    new string[] { "instruction" },
                    new string[] { "data_definition_statement" },
                })

                .AddNonCollapsingSymbolRule(
                "proc_element_sequence",
                new string[][]
                {
                    new string[] { "proc_element", "proc_element_sequence" },
                    new string[] { "proc_element" },
                })

                .AddCollapsingSymbolRule(
                "procedure",
                (new string[] { "proc", "{", "proc_element_sequence", "}" },
                (NodeWrapper<Symbol> node) =>
                {
                    Symbol s = new Procedure(node.FirstNode);
                    return (s, node.GetNode(s.ChildSymbols.Count - 1));
                }))

                .AddNonCollapsingSymbolRule(
                "asm_file_element",
                new string[][]
                {
                    new string[] { "directive" },
                    new string[] { "data_definition_statement" },
                    new string[] { "instruction" },
                    new string[] { "procedure" },
                })

                .AddNonCollapsingSymbolRule(
                "asm_file_element_sequence",
                new string[][]
                {
                    new string[] { "asm_file_element", "asm_file_element_sequence" },
                    new string[] { "asm_file_element" },
                })

                .AddCollapsingSymbolRule(
                ROOT_RULE_NAME,
                ("asm_file_element_sequence", (NodeWrapper<Symbol> node) => (new AsmFile(node.FirstNode), node.FirstNode.List.Last)),
                ("", (NodeWrapper<Symbol> node) => (new AsmFile(node.FirstNode), node.FirstNode.List.Last))
                );

            Symbols = storeBuilder.Dictionary;
        }
    }
}