using System;
using System.Collections.Generic;
using System.IO;

using Antlr4.Runtime;
using Antlr4.Runtime.Tree;
using Antlr4.Runtime.Misc;
using Antlr4.Runtime.Dfa;
using Antlr4.Runtime.Sharpen;
using Antlr4.Runtime.Atn;

namespace PulsarAssembler
{
    class PulsarAsmLexerErrorListener : ConsoleErrorListener<int>
    {
        public bool WasError { get; private set; }
        public AggregateException Exception
        {
            get
            {
                return new AggregateException(exceptions);
            }
        }

        private List<RecognitionException> exceptions = new List<RecognitionException>();

        public override void SyntaxError(TextWriter output, IRecognizer recognizer, int offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
        {
            WasError = true;
            exceptions.Add(e);
        }
    }

    class PulsarAsmParserErrorListener : ConsoleErrorListener<IToken>
    {
        public bool WasError { get; private set; }
        public AggregateException Exception { get; private set; }

        private List<RecognitionException> exceptions = new List<RecognitionException>();

        public override void SyntaxError(TextWriter output, IRecognizer recognizer, IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
        {
            WasError = true;
            exceptions.Add(e);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length != 2)
                {
                    Console.WriteLine("Need 2 arguments: <inputPath> - path to assembly source, <outputPath> - path to binary");
                    return;
                }
                Console.WriteLine("Opening files...");
                PulsarAsmParserErrorListener parserErrorlistener = new PulsarAsmParserErrorListener();
                PulsarAsmLexerErrorListener lexerErrorListener = new PulsarAsmLexerErrorListener();
                using FileStream inStream = new FileStream(args[0], FileMode.Open);
                using FileStream outStream = new FileStream(args[1], FileMode.Create);
                ICharStream charStream = CharStreams.fromStream(inStream);
                ICharStream upper = new CaseChangingCharStream(charStream, true);
                PulsarAsmGrammarLexer lexer = new PulsarAsmGrammarLexer(upper);
                lexer.AddErrorListener(lexerErrorListener);
                ITokenStream tokens = new CommonTokenStream(lexer);
                PulsarAsmGrammarParser parser = new PulsarAsmGrammarParser(tokens)
                {
                    BuildParseTree = true,
                };
                parser.AddErrorListener(parserErrorlistener);
                Console.WriteLine("Parsing...");
                var tree = parser.asm_file();
                if (lexerErrorListener.WasError)
                {
                    if (lexerErrorListener.Exception != null)
                    {
                        throw lexerErrorListener.Exception;
                    }
                    else
                    {
                        throw new InvalidOperationException("Lexer failed");
                    }
                }
                if (parserErrorlistener.WasError)
                {
                    if (parserErrorlistener.Exception != null)
                    {
                        throw parserErrorlistener.Exception;
                    }
                    else
                    {
                        throw new InvalidOperationException("Parser failed");
                    }
                }
                PulsarAsmCodeGenerator l = new PulsarAsmCodeGenerator();
                ParseTreeWalker.Default.Walk(l, tree);
                Console.WriteLine("Emitting binary...");
                l.EmitBinary(outStream);
                Console.WriteLine("Done");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
