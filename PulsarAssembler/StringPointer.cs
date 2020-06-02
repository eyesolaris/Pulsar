using Microsoft.VisualBasic.CompilerServices;
using System;
using System.Reflection.Metadata.Ecma335;

namespace PulsarAssembler
{
    public struct StringPointer
    {
        /// Индекс, равный длине строки, обозначает конец строки
        public StringPointer(string str, uint position = 0)
        {
            if (position > str.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(position), position, "String index out of range");
            }
            String = str;
            currentPosition = position;
        }

        public string String { get; }
        private uint currentPosition;
        public uint CurrentPosition
        {
            get
            {
                return currentPosition;
            }

            set
            {
                if (InRange(value))
                {
                    currentPosition = value;
                }
                else
                {
                    throw new ArgumentOutOfRangeException(nameof(value), value, $"value > {String.Length}");
                }
            }
        }
        public char Symbol { get => String[(int)CurrentPosition]; }

        public bool MoveNext()
        {
            if (CurrentPosition < Length)
            {
                CurrentPosition++;
                return true;
            }
            return false;
        }

        public bool EndLine { get => CurrentPosition == Length; }

        public bool MovePrevious()
        {
            if (CurrentPosition > 0)
            {
                CurrentPosition--;
                return true;
            }
            return false;
        }

        public static StringPointer operator++(StringPointer pointer)
        {
            pointer.CurrentPosition++;
            return pointer;
        }

        public static StringPointer operator--(StringPointer pointer)
        {
            pointer.CurrentPosition--;
            return pointer;
        }

        public static StringPointer operator+(StringPointer pointer, uint offset)
        {
            return new StringPointer(pointer.String, pointer.CurrentPosition + offset);
        }

        public static StringPointer operator-(StringPointer pointer, uint offset)
        {
            return new StringPointer(pointer.String, pointer.CurrentPosition - offset);
        }

        public ReadOnlySpan<char> AsSpan()
        {
            return String.AsSpan((int)CurrentPosition);
        }

        public string AsString()
        {
            return String.Substring((int)CurrentPosition);
        }

        public ReadOnlySpan<char> AsSpan(int length)
        {
            return String.AsSpan((int)CurrentPosition, length);
        }

        public override string ToString()
        {
            return string.Format("\"{0}\", \"{1}\"", String.Substring((int)CurrentPosition), String);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(String, CurrentPosition);
        }

        public void SetToEnd()
        {
            CurrentPosition = Length;
        }

        public void SetToStart()
        {
            CurrentPosition = 0;
        }

        public uint LastIndex
        {
            get
            {
                return Length - 1;
            }
        }

        public uint Length
        {
            get
            {
                return (uint)String.Length;
            }
        }

        private bool InRange(uint index)
        {
            return index <= String.Length;
        }
    }
}