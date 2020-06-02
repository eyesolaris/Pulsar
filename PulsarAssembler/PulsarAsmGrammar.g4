grammar PulsarAsmGrammar;

/*
Parser rules
*/

bitness_directive: BITNESS DECIMAL_INTEGER ;
address_directive: ADDRESSES DECIMAL_INTEGER ;
directive : bitness_directive | address_directive | ENDIANNESS_LITTLE | ENDIANNESS_BIG ;
proc_header : PROC IDENTIFIER ;
instruction_specifier : DATA_TYPE_SPECIFIER | ADDRESS_TYPE_SPECIFIER | UNALIGNED ;
unsigned_integer : BIN_INTEGER | DECIMAL_INTEGER | HEX_INTEGER ;
integer : unsigned_integer | SIGNED_DECIMAL_INTEGER ;
data_definition : integer | TEXT_STRING ;
data_definition_sequence_inner : data_definition COMMA data_definition_sequence_inner | data_definition COMMA ;
data_definition_sequence : data_definition_sequence_inner data_definition | data_definition ;
data_identifier : IDENTIFIER | ;
data_definition_statement : DATA_TYPE_SPECIFIER data_identifier data_definition_sequence ;
op_immediate : OFFSET IDENTIFIER | integer ;
op_register : GP_REGISTER | INFO_REGISTER | SYSTEM_REGISTER ;
op_imm_memory : SQ_L integer SQ_R ;
op_indirect : SQ_L GP_REGISTER SQ_R ;
op_local : LOCAL SQ_L integer SQ_R ;
op_base_w_offset : SQ_L GP_REGISTER SIGN unsigned_integer SQ_R ;
op_base_w_register : SQ_L GP_REGISTER PLUS GP_REGISTER SQ_R ;
op_relative : TILD integer;
op_data : IDENTIFIER ;
jmp_operand : op_imm_memory | op_indirect | op_local | op_base_w_offset | op_base_w_register | op_relative | op_data ;
st_operand : op_register | jmp_operand ;
operands :
	st_operand COMMA st_operand COMMA op_immediate |
	st_operand COMMA st_operand COMMA st_operand |
	st_operand COMMA op_immediate |
	st_operand COMMA st_operand |
	op_immediate |
	st_operand |
	;
label: IDENTIFIER COLON | ;
instr_specifier_sequence :
	instruction_specifier instr_specifier_sequence |
	;
	
instr_body :
	label MNEMONIC instr_specifier_sequence operands ;

jump_sequence:
	jmp_operand COMMA jmp_operand |
	jmp_operand ;
	
conditional_body_shared :
	instr_body COMMA CONDITION ;

conditional_instruction :
	conditional_body_shared jump_sequence ;
	
conditional_cp_instruction :
	conditional_body_shared SETBOOL st_operand ;

instruction :
	conditional_instruction |
	conditional_cp_instruction |
	instr_body ;

proc_element :
	instruction |
	data_definition_statement ;

proc_element_sequence :
	proc_element proc_element_sequence |
	proc_element ;

procedure :
	proc_header PROC_START proc_element_sequence PROC_END ;

asm_file_element :
	directive |
	data_definition_statement |
	instruction |
	procedure ;

asm_file_element_sequence :
	asm_file_element asm_file_element_sequence |
	asm_file_element ;

asm_file :
	asm_file_element_sequence |
	;

/********************************************************/
/*
Lexer rules
*/

fragment IDENTIFIER_STARTING_CHAR : 'A'..'Z' | 'a'..'z' ;
fragment DIGIT : '0'..'9' ;
fragment IDENTIFIER_CHAR : IDENTIFIER_STARTING_CHAR | DIGIT ;
fragment BIN_DIGIT : '0' | '1' ;
fragment HEX_DIGIT : '0'..'9' | 'A'..'F' | 'a'..'f' ;


fragment NEWLINE_CHAR : ('\r'? '\n' | '\r') ;
WHITESPACE : (' ' | '\t') -> skip;

NEWLINE : NEWLINE_CHAR+ -> skip;
COMMENTARY : '//' .*? (NEWLINE | EOF ) -> skip ;


MNEMONIC :
	'INVALID' | 'NOP' | 'RET' | 'INT' | 'SYSCALL' | 'CHNGMODE' | 'SMCODST' | 'SMCODEND' | 'SYSID' | 'ALLOCVARS' | 'DBGINT' | 'GETRETPTR' | 'SETRETPTR' | 'CLRST' | 'GETCDPTR' | 'CPYZX' | 'CPYSX' | 'LOADCTX' | 'SAVECTX' | 'CALLNAT' | 'JMPNAT' | 'RDINFOREG' | 'FWCALL' | 'JMPUSR' | 'RDSYSREG' | 'WRSYSREG' | 'RDPORT' | 'WRPORT' | 'PRRDSTATREG' | 'FBDINT' | 'ALWINT' | 'GETINTFLAG' | 'IRET' | 'RESTREG' | 'STRREG' | 'CALL' | 'ZERO' | 'FILL' | 'NOT' | 'NEG' | 'SHR' | 'SHL' | 'SAR' | 'RTR' | 'RTL' | 'INCR' | 'DECR' | 'PUSH' | 'POP' | 'ALIGNLEFT' | 'ALIGNRIGHT' | 'GETFROMD' | 'SETFROMD' | 'RDTCKS' | 'GETIP' | 'GETSTREG' | 'SETSTREG' | 'JMP' | 'GETCTXSZ' | 'GETCAPTR' | 'FTRUNC' | 'FTONTTE' | 'FTONTAFZ' | 'FROTOPINF' | 'FROTOMINF' | 'RDSTATREG' | 'ADD' | 'SUB' | 'MUL' | 'DIV' | 'IDIV' | 'AND' | 'OR' | 'XOR' | 'NOR' | 'ADDO' | 'SUBO' | 'MULO' | 'GETBIT' | 'SETBIT' | 'INVBIT' | 'JUMPIF' | 'CPY' | 'REM' | 'IREM' | 'NAND' | 'ADDS' | 'SUBS' | 'MULS' | 'ADDSS' | 'SUBSS' | 'MULSS' | 'FADD' | 'FSUB' | 'FMUL' | 'FDIV';

PLUS : '+' ;
SIGN : PLUS | '-' ;
COMMA : ',' ;
DECIMAL_INTEGER : DIGIT+ ;
SIGNED_DECIMAL_INTEGER : SIGN DECIMAL_INTEGER ;
BIN_INTEGER : '0' [Bb] BIN_DIGIT+ ;
HEX_INTEGER : '0' [Xx] HEX_DIGIT+ ;

BITNESS: '.BITNESS' ;
ADDRESSES: '.ADDRESSES' ;
ENDIANNESS_LITTLE: '.LITTLEENDIAN' ;
ENDIANNESS_BIG : '.BIGENDIAN' ;
DATA_TYPE_SPECIFIER : '.I8' | '.I16' | '.I32' | '.I64' ;
ADDRESS_TYPE_SPECIFIER : '.A8' | '.A16' | '.A32' | '.A64' ;
UNALIGNED : '.UNALIGNED' ;

GP_REGISTER: 'R0' | 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6' | 'R7' | 'R8' | 'R9' | 'R10' | 'R11' | 'R12' | 'R13' | 'R14' | 'R15' ;
SYSTEM_REGISTER : 'SR' DECIMAL_INTEGER ;
INFO_REGISTER : 'IR' DECIMAL_INTEGER ;

CONDITION : 'ZER' | 'NZER' | 'NEGATIVE' | 'POSITIVE' | 'CARRY' | 'NCARRY' | 'OVF' | 'NOVF' | 'EQUAL' | 'NEQUAL' | 'ULESS' | 'UGREATEREQ' | 'ULESSEQ' | 'UGREATER' | 'SLESS' | 'SGREATEREQ' | 'SLESSEQ' | 'SGREATER' | 'PARITY' | 'PARITYEVEN' | 'NPARITY' | 'PARITYODD' | 'HALFCARRY' | 'NHALFCARRY' | 'UMAX' | 'NUMAX' | 'UMIN' | 'NUMIN' | 'MINUSONE' | 'NMINUSONE' | 'SMAX' | 'NSMAX' | 'SMIN' | 'NSMIN' | 'ONE' | 'NOTONE' | 'TRUE' | 'FALSE' ;
PROC: '.PROC' ;
PROC_START : '{' ;
PROC_END : '}' ;
SQ_L : '[' ;
SQ_R : ']' ;
TILD : '~' ;
COLON : ':' ;
OFFSET : 'OFFSET' ;
LOCAL : 'LOCAL' ;
SETBOOL: 'SETBOOL' ;

TEXT_STRING : '"' ('\\' | '!' | '`' | '~' | '@' | '#' | '$' | '%' | '^' | '&' | '*' | '(' | ')' | '-' | '_' | '+' | '=' | '|' | '/' | '.' | ',' | '\'' | ':' | '?' | '<' | '>' | '\\"' | '(' | ')' | ' ' | '\t' | IDENTIFIER_CHAR)+ '"';

IDENTIFIER : IDENTIFIER_STARTING_CHAR IDENTIFIER_CHAR* ;

/* _type, _text, _channel, _tokenStartCharIndex, _tokenStartLine, and _tokenStartCharPositionInLine */