/*
*	Copyright (c) 2010, Greg Rogers
*
*	This source code is released for free distribution under the terms of the
*	GNU General Public License.
*
*	This module contains functions for parsing and scanning ASN.1 files.
*/

/*
 *	 INCLUDE FILES
 */
#include "general.h"

#include <string.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>

#include "debug.h"
#include "entry.h"
#include "keyword.h"
#include "options.h"
#include "read.h"
#include "routines.h"
#include "vstring.h"

/*
 *	 MACROS
 */

#define isType(token,t)		(boolean) ((token)->type == (t))
#define isKeyword(token,k)	(boolean) ((token)->keyword == (k))

/*
 *	 DATA DECLARATIONS
 */

typedef enum eException
{
	ExceptionNone,
	ExceptionEOF,
	ExceptionParseError
} exception_t;

/*	Used to specify type of keyword. */
typedef enum eKeywordId {
	KEYWORD_NONE = -1,
	KEYWORD_ABSENT,
	KEYWORD_ABSTRACT_SYNTAX,
	KEYWORD_ALL,
	KEYWORD_APPLICATION,
	KEYWORD_AUTOMATIC,
	KEYWORD_BEGIN,
	KEYWORD_BIT,
	KEYWORD_BMPString,
	KEYWORD_BOOLEAN,
	KEYWORD_BY,
	KEYWORD_CHARACTER,
	KEYWORD_CHOICE,
	KEYWORD_CLASS,
	KEYWORD_COMPONENT,
	KEYWORD_COMPONENTS,
	KEYWORD_CONSTRAINED,
	KEYWORD_CONTAINING,
	KEYWORD_DEFAULT,
	KEYWORD_DEFINITIONS,
	KEYWORD_EMBEDDED,
	KEYWORD_ENCODED,
	KEYWORD_END,
	KEYWORD_ENUMERATED,
	KEYWORD_EXCEPT,
	KEYWORD_EXPLICIT,
	KEYWORD_EXPORTS,
	KEYWORD_EXTENSIBILITY,
	KEYWORD_EXTERNAL,
	KEYWORD_FALSE,
	KEYWORD_FROM,
	KEYWORD_GeneralString,
	KEYWORD_GeneralizedTime,
	KEYWORD_GraphicString,
	KEYWORD_IA5String,
	KEYWORD_IDENTIFIER,
	KEYWORD_IMPLICIT,
	KEYWORD_IMPLIED,
	KEYWORD_IMPORTS,
	KEYWORD_INCLUDES,
	KEYWORD_INSTANCE,
	KEYWORD_INTEGER,
	KEYWORD_INTERSECTION,
	KEYWORD_ISO646String,
	KEYWORD_MAX,
	KEYWORD_MIN,
	KEYWORD_MINUS_INFINITY,
	KEYWORD_NULL,
	KEYWORD_NumericString,
	KEYWORD_OBJECT,
	KEYWORD_OCTET,
	KEYWORD_OF,
	KEYWORD_OPTIONAL,
	KEYWORD_ObjectDescriptor,
	KEYWORD_PATTERN,
	KEYWORD_PDV,
	KEYWORD_PLUS_INFINITY,
	KEYWORD_PRESENT,
	KEYWORD_PRIVATE,
	KEYWORD_PrintableString,
	KEYWORD_REAL,
	KEYWORD_RELATIVE_OID,
	KEYWORD_SEQUENCE,
	KEYWORD_SET,
	KEYWORD_SIZE,
	KEYWORD_STRING,
	KEYWORD_SYNTAX,
	KEYWORD_T61String,
	KEYWORD_TAGS,
	KEYWORD_TRUE,
	KEYWORD_TYPE_IDENTIFIER,
	KEYWORD_TeletexString,
	KEYWORD_UNION,
	KEYWORD_UNIQUE,
	KEYWORD_UNIVERSAL,
	KEYWORD_UTCTime,
	KEYWORD_UTF8String,
	KEYWORD_UniversalString,
	KEYWORD_VideotexString,
	KEYWORD_VisibleString,
	KEYWORD_WITH
} keywordId;

typedef struct sKeywordDesc {
	const char *name;
	keywordId id;
} keywordDesc;

typedef enum eTokenType {
	TOKEN_NONE,
	TOKEN_BRACE_OPEN,
	TOKEN_BRACE_CLOSE,
	TOKEN_PAREN_OPEN,
	TOKEN_PAREN_CLOSE,
	TOKEN_ANGLE_BRACKET_OPEN,
	TOKEN_ANGLE_BRACKET_CLOSE,
	TOKEN_ASSIGNMENT,
	TOKEN_SEMICOLON,
	TOKEN_PIPE,
	TOKEN_PERIOD,
	TOKEN_KEYWORD,
	TOKEN_UPPER_IDENTIFIER,
	TOKEN_LOWER_IDENTIFIER
} tokenType;

typedef struct sTokenInfo {
	tokenType		type;
	keywordId		keyword;
	vString *		string;
	vString *		scope;
	unsigned long	lineNumber;
	fpos_t			filePosition;
} tokenInfo;

/*
 *	DATA DEFINITIONS
 */
static langType Lang_asn;

static jmp_buf Exception;

static vString *modulereference;
static vString *identifier;

typedef enum {
	/* K_CLASS, */ K_ENUMERATOR, K_MEMBER, K_MODULE, K_TYPE, K_VALUE
} asnKind;

static kindOption AsnKinds[] = {
	/* {TRUE,	'c', "class",	"classes"}, */
	{TRUE,	'e', "enumerator",	"enumerators (names defined in an enumerated type)"},
	{TRUE,	'm', "member",		"set or sequence members"},
	{TRUE,	'n', "module",		"module definitions"},
	{TRUE,	't', "type",		"type definitions"},
	{TRUE,	'v', "value",		"value definitions"},
};

static const keywordDesc AsnKeywordTable[] = {
	/* keyword				keyword ID */
	{"ABSENT",				KEYWORD_ABSENT				},
	{"ABSTRACT_SYNTAX",		KEYWORD_ABSTRACT_SYNTAX		},
	{"ALL",					KEYWORD_ALL					},
	{"APPLICATION",			KEYWORD_APPLICATION			},
	{"AUTOMATIC",			KEYWORD_AUTOMATIC			},
	{"BEGIN",				KEYWORD_BEGIN				},
	{"BIT",					KEYWORD_BIT					},
	{"BMPString",			KEYWORD_BMPString			},
	{"BOOLEAN",				KEYWORD_BOOLEAN				},
	{"BY",					KEYWORD_BY					},
	{"CHARACTER",			KEYWORD_CHARACTER			},
	{"CHOICE",				KEYWORD_CHOICE				},
	{"CLASS",				KEYWORD_CLASS				},
	{"COMPONENT",			KEYWORD_COMPONENT			},
	{"COMPONENTS",			KEYWORD_COMPONENTS			},
	{"CONSTRAINED",			KEYWORD_CONSTRAINED			},
	{"CONTAINING",			KEYWORD_CONTAINING			},
	{"DEFAULT",				KEYWORD_DEFAULT				},
	{"DEFINITIONS",			KEYWORD_DEFINITIONS			},
	{"EMBEDDED",			KEYWORD_EMBEDDED			},
	{"ENCODED",				KEYWORD_ENCODED				},
	{"END",					KEYWORD_END					},
	{"ENUMERATED",			KEYWORD_ENUMERATED			},
	{"EXCEPT",				KEYWORD_EXCEPT				},
	{"EXPLICIT",			KEYWORD_EXPLICIT			},
	{"EXPORTS",				KEYWORD_EXPORTS				},
	{"EXTENSIBILITY",		KEYWORD_EXTENSIBILITY		},
	{"EXTERNAL",			KEYWORD_EXTERNAL			},
	{"FALSE",				KEYWORD_FALSE				},
	{"FROM",				KEYWORD_FROM				},
	{"GeneralString",		KEYWORD_GeneralString		},
	{"GeneralizedTime",		KEYWORD_GeneralizedTime		},
	{"GraphicString",		KEYWORD_GraphicString		},
	{"IA5String",			KEYWORD_IA5String			},
	{"IDENTIFIER",			KEYWORD_IDENTIFIER			},
	{"IMPLICIT",			KEYWORD_IMPLICIT			},
	{"IMPLIED",				KEYWORD_IMPLIED				},
	{"IMPORTS",				KEYWORD_IMPORTS				},
	{"INCLUDES",			KEYWORD_INCLUDES			},
	{"INSTANCE",			KEYWORD_INSTANCE			},
	{"INTEGER",				KEYWORD_INTEGER				},
	{"INTERSECTION",		KEYWORD_INTERSECTION		},
	{"ISO646String",		KEYWORD_ISO646String		},
	{"MAX",					KEYWORD_MAX					},
	{"MIN",					KEYWORD_MIN					},
	{"MINUS-INFINITY",		KEYWORD_MINUS_INFINITY		},
	{"NULL",				KEYWORD_NULL				},
	{"NumericString",		KEYWORD_NumericString		},
	{"OBJECT",				KEYWORD_OBJECT				},
	{"OCTET",				KEYWORD_OCTET				},
	{"OF",					KEYWORD_OF					},
	{"OPTIONAL",			KEYWORD_OPTIONAL			},
	{"ObjectDescriptor",	KEYWORD_ObjectDescriptor	},
	{"PATTERN",				KEYWORD_PATTERN				},
	{"PDV",					KEYWORD_PDV					},
	{"PLUS-INFINITY",		KEYWORD_PLUS_INFINITY		},
	{"PRESENT",				KEYWORD_PRESENT				},
	{"PRIVATE",				KEYWORD_PRIVATE				},
	{"PrintableString",		KEYWORD_PrintableString		},
	{"REAL",				KEYWORD_REAL				},
	{"RELATIVE-OID",		KEYWORD_RELATIVE_OID		},
	{"SEQUENCE",			KEYWORD_SEQUENCE			},
	{"SET",					KEYWORD_SET					},
	{"SIZE",				KEYWORD_SIZE				},
	{"STRING",				KEYWORD_STRING				},
	{"SYNTAX",				KEYWORD_SYNTAX				},
	{"T61String",			KEYWORD_T61String			},
	{"TAGS",				KEYWORD_TAGS				},
	{"TRUE",				KEYWORD_TRUE				},
	{"TYPE-IDENTIFIER",		KEYWORD_TYPE_IDENTIFIER		},
	{"TeletexString",		KEYWORD_TeletexString		},
	{"UNION",				KEYWORD_UNION				},
	{"UNIQUE",				KEYWORD_UNIQUE				},
	{"UNIVERSAL",			KEYWORD_UNIVERSAL			},
	{"UTCTime",				KEYWORD_UTCTime				},
	{"UTF8String",			KEYWORD_UTF8String			},
	{"UniversalString",		KEYWORD_UniversalString		},
	{"VideotexString",		KEYWORD_VideotexString		},
	{"VisibleString",		KEYWORD_VisibleString		},
	{"WITH",				KEYWORD_WITH				},
};

/*
 *	 FUNCTION DEFINITIONS
 */

static void parseType(tokenInfo *const token);

static boolean isnewline(const int c)
{
	return c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static boolean isKeywordAnyOf(const tokenInfo *const token, ...)
{
	va_list ap;
	boolean ret = FALSE;
	keywordId keyword;

	va_start(ap, token);
	while ((keyword = va_arg(ap, keywordId)) != KEYWORD_NONE)
		ret = ret || isKeyword(token, keyword);

	va_end(ap);
	return ret;
}

static tokenInfo *newToken(void)
{
	tokenInfo *const token = xMalloc(1, tokenInfo);

	token->type			= TOKEN_NONE;
	token->keyword		= KEYWORD_NONE;
	token->string		= vStringNew();
	token->scope		= vStringNew();
	token->lineNumber	= getSourceLineNumber();
	token->filePosition = getInputFilePosition();

	return token;
}

static void deleteToken(tokenInfo *const token)
{
	vStringDelete(token->string);
	vStringDelete(token->scope);
	eFree(token);
}

static void skipSingleLineComment(void)
{
	int c;
	do
	{
		c = fileGetc();
		if (isnewline(c))
			break;
		else if (c == '-')
		{
			c = fileGetc();
			if (c == '-')
				break;
			else
				fileUngetc(c);
		}
	}
	while (c != EOF && c != '\0');
}

static void skipMultiLineComment(void)
{
	int c;
	int nesting = 1;
	do
	{
		c = fileGetc();
		if (c == '*')
		{
			c = fileGetc();
			if (c == '/')
				--nesting;
			else
				fileUngetc(c);
		}
		else if (c == '/')
		{
			c = fileGetc();
			if (c == '*')
				++nesting;
			else
				fileUngetc(c);
		}
	}
	while (c != EOF && c != '\0' && nesting > 0);
}

static void parseIdentifier(vString *const string, const int firstChar)
{
	int c = firstChar;
	while (TRUE)
	{
		vStringPut(string, c);
		c = fileGetc();
		if (c == '-')
		{
			int d = fileGetc();
			if (d == '-' || !isalnum(d))
			{
				fileUngetc(d);
				fileUngetc(c);
				break;
			}
			fileUngetc(d);
		}
		else if (!isalnum(c))
		{
			fileUngetc(c);
			break;
		}
	}
	vStringTerminate(string);
}

static void readToken(tokenInfo *const token)
{
	int c;

	token->type		= TOKEN_NONE;
	token->keyword	= KEYWORD_NONE;
	vStringClear(token->string);
	vStringClear(token->scope);

getNextChar:
	do
	{
		c = fileGetc ();
		token->lineNumber	= getSourceLineNumber ();
		token->filePosition = getInputFilePosition ();
	}
	while (isspace(c));

	switch (c)
	{
		case EOF: longjmp(Exception, ExceptionEOF);			break;
		case '{': token->type = TOKEN_BRACE_OPEN;			break;
		case '}': token->type = TOKEN_BRACE_CLOSE;			break;
		case '(': token->type = TOKEN_PAREN_OPEN;			break;
		case ')': token->type = TOKEN_PAREN_CLOSE;			break;
		case '<': token->type = TOKEN_ANGLE_BRACKET_OPEN;	break;
		case '>': token->type = TOKEN_ANGLE_BRACKET_CLOSE;	break;
		case ';': token->type = TOKEN_SEMICOLON;			break;
		case '|': token->type = TOKEN_PIPE;					break;
		case '.': token->type = TOKEN_PERIOD;				break;
		case ':':
			{
				int d1 = fileGetc();
				if (d1 == ':')
				{
					int d2 = fileGetc();
					if (d2 == '=')
					{
						token->type = TOKEN_ASSIGNMENT;
						break;
					}
					else
						fileUngetc(d2);
				}

				fileUngetc(d1);
				token->type = TOKEN_NONE;
				break;
			}

		case '-':
			{
				int d = fileGetc();
				if (d == '-')
				{
					skipSingleLineComment();
					goto getNextChar;
				}
				else
				{
					fileUngetc(d);
					token->type = TOKEN_NONE;
				}
				break;
			}

		case '/':
			{
				int d = fileGetc();
				if (d == '*')
				{
					skipMultiLineComment();
					goto getNextChar;
				}
				else
				{
					fileUngetc(d);
					/* note: forward slash is not a valid token on its own! */
					token->type = TOKEN_NONE;
				}
				break;
			}

		default:
			if (islower(c))
			{
				parseIdentifier(token->string, c);
				token->type = TOKEN_LOWER_IDENTIFIER;
				token->lineNumber = getSourceLineNumber();
				token->filePosition = getInputFilePosition();
			}
			else if (isupper(c))
			{
				parseIdentifier(token->string, c);
				token->lineNumber = getSourceLineNumber();
				token->filePosition = getInputFilePosition();
				token->keyword = lookupKeyword(vStringValue(token->string),
						Lang_asn);
				if (isKeyword(token, KEYWORD_NONE))
					token->type = TOKEN_UPPER_IDENTIFIER;
				else
					token->type = TOKEN_KEYWORD;
			}
			else
				token->type = TOKEN_NONE;
			break;
	}
}

static void skipPastToken(tokenInfo *const token, tokenType type)
{
	while (!isType(token, type))
		readToken(token);

	readToken(token);
}

static void skipPastNestedToken(tokenInfo *const token, tokenType openType,
		tokenType closeType)
{
	int nesting = 0;

	do
	{
		if (isType(token, openType))
			++nesting;
		else if (isType(token, closeType))
			--nesting;

		readToken(token);
	}
	while (nesting > 0);
}

static void skipPastKeyword(tokenInfo *const token, keywordId keyword)
{
	while (!isKeyword(token, keyword))
		readToken(token);

	readToken(token);
}

static void addScopeQualifier(vString *const string)
{
	vStringCatS(string, ".");
}

static void addToScope(tokenInfo *const token, const vString *const string)
{
	if (vStringLength(token->scope) > 0)
		addScopeQualifier(token->scope);

	vStringCat(token->scope, string);
}

static void makeAsnTag(const tokenInfo *const token, const asnKind kind)
{
	tagEntryInfo e;

	if (AsnKinds[kind].enabled)
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n makeAsnTag token;  scope:%s  name:%s\n",
					vStringValue(token->scope),
					vStringValue(token->string));
				);

		initTagEntry(&e, vStringValue(token->string));

		e.lineNumber	= token->lineNumber;
		e.filePosition	= token->filePosition;
		e.kindName		= AsnKinds[kind].name;
		e.kind			= AsnKinds[kind].letter;
		/*
		 * FIXME - keep track of EXPORTS, and set file scope to false if the
		 * symbol is exported from the module
		 */
		e.isFileScope	= TRUE;

		makeTagEntry(&e);

		if (Option.include.qualifiedTags && vStringLength(token->scope) > 0)
		{
			vString *const scopedName = vStringNew();

			vStringCopy(scopedName, token->scope);
			addScopeQualifier(scopedName);
			vStringCatS(scopedName, e.name);
			e.name = vStringValue(scopedName);

			makeTagEntry(&e);

			vStringDelete(scopedName);
		}
	}
}

static void parseExports(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_EXPORTS))
		return;

	skipPastToken(token, TOKEN_SEMICOLON);
}

static void parseImports(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_IMPORTS))
		return;

	skipPastToken(token, TOKEN_SEMICOLON);
}

static boolean parseConstraint(tokenInfo *const token)
{
	if (!isType(token, TOKEN_PAREN_OPEN))
		return FALSE;

	skipPastNestedToken(token, TOKEN_PAREN_OPEN, TOKEN_PAREN_CLOSE);
	return TRUE;
}

static boolean parseSizeConstraint(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_SIZE))
		return FALSE;

	readToken(token);
	if (!parseConstraint(token))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:(, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	return TRUE;
}

static boolean parseBitStringType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_BIT))
		return FALSE;

	readToken(token);
	if (!isKeyword(token, KEYWORD_STRING))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:STRING, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	if (isType(token, TOKEN_BRACE_OPEN)) /* NamedBitList - FIXME */
		skipPastNestedToken(token, TOKEN_BRACE_OPEN, TOKEN_BRACE_CLOSE);

	return TRUE;
}

static boolean parseBooleanType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_BOOLEAN))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseRestrictedCharacterStringType(tokenInfo *const token)
{
	if (!isKeywordAnyOf(token, KEYWORD_BMPString, KEYWORD_GeneralString,
				KEYWORD_GraphicString, KEYWORD_IA5String, KEYWORD_ISO646String,
				KEYWORD_NumericString, KEYWORD_PrintableString,
				KEYWORD_TeletexString, KEYWORD_T61String,
				KEYWORD_UniversalString, KEYWORD_UTF8String,
				KEYWORD_VideotexString, KEYWORD_VisibleString, KEYWORD_NONE))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseUnrestrictedCharacterStringType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_CHARACTER))
		return FALSE;

	readToken(token);
	if (!isKeyword(token, KEYWORD_STRING))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:STRING, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	return TRUE;
}

static boolean parseCharacterStringType(tokenInfo *const token)
{
	return parseUnrestrictedCharacterStringType(token) ||
		parseRestrictedCharacterStringType(token);
}

static boolean parseChoiceType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_CHOICE))
		return FALSE;

	readToken(token);
	if (isType(token, TOKEN_BRACE_OPEN))
		skipPastNestedToken(token, TOKEN_BRACE_OPEN, TOKEN_BRACE_CLOSE);

	return TRUE;
}

static boolean parseEmbeddedPDVType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_EMBEDDED))
		return FALSE;

	readToken(token);
	if (!isKeyword(token, KEYWORD_PDV))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:PDV, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	return TRUE;
}

static void parseEnumerations(tokenInfo *const token)
{
	/* FIXME */
}

static boolean parseEnumeratedType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_ENUMERATED))
		return FALSE;

	readToken(token);
	if (isType(token, TOKEN_BRACE_OPEN))
		skipPastNestedToken(token, TOKEN_BRACE_OPEN, TOKEN_BRACE_CLOSE);
	/*
	readToken(token);
	if (!isToken(token, TOKEN_BRACE_OPEN))
		return FALSE;

	readToken(token);
	parseEnumerations(token);

	readToken(token);
	if (!isToken(token, TOKEN_BRACE_CLOSE))
		return FALSE;
		*/

	return TRUE;
}

static boolean parseExternalType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_EXTERNAL))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseInstanceOfType(tokenInfo *const token)
{
	return FALSE; /* FIXME X.681 */
}

static boolean parseIntegerType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_INTEGER))
		return FALSE;

	readToken(token);
	if (isType(token, TOKEN_BRACE_OPEN)) /* NamedNumberList - FIXME */
		skipPastNestedToken(token, TOKEN_BRACE_OPEN, TOKEN_BRACE_CLOSE);

	return TRUE;
}

static boolean parseNullType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_NULL))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseObjectClassFieldType(tokenInfo *const token)
{
	return FALSE; /* FIXME X.681 */
}

static boolean parseObjectIdentifierType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_OBJECT))
		return FALSE;

	readToken(token);
	if (!isKeyword(token, KEYWORD_IDENTIFIER))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:IDENTIFIER, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	return TRUE;
}

static boolean parseOctetStringType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_OCTET))
		return FALSE;

	readToken(token);
	if (!isKeyword(token, KEYWORD_STRING))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:STRING, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	return TRUE;
}

static boolean parseRealType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_REAL))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseRelativeOIDType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_RELATIVE_OID))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseSequenceType(tokenInfo *const token)
{
	if (!isType(token, TOKEN_BRACE_OPEN))
		return FALSE;

	/* FIXME */
	skipPastNestedToken(token, TOKEN_BRACE_OPEN, TOKEN_BRACE_CLOSE);
	return TRUE;
}

static boolean parseSequenceOfType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_OF))
		return FALSE;

	/* FIXME parse NamedType - there is an ambiguity that needs 2 tokens of
	 * lookahead (SelectionType also starts with an identifier)
	 */
	readToken(token);
	parseType(token);
	return TRUE;
}

static boolean parseConstrainedSequenceOfType(tokenInfo *const token)
{
	if (!parseSizeConstraint(token) && !parseConstraint(token))
		return FALSE;

	return parseSequenceOfType(token);
}

static boolean parseSequenceXxxType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_SEQUENCE))
		return FALSE;

	readToken(token);
	if (!parseSequenceType(token) && !parseConstrainedSequenceOfType(token) &&
			!parseSequenceOfType(token))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected either:{, OF, (, SIZE, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	return TRUE;
}

static boolean parseSetType(tokenInfo *const token)
{
	if (!isType(token, TOKEN_BRACE_OPEN))
		return FALSE;

	/* FIXME */
	skipPastNestedToken(token, TOKEN_BRACE_OPEN, TOKEN_BRACE_CLOSE);
	return TRUE;
}

static boolean parseSetOfType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_OF))
		return FALSE;

	/* FIXME parse NamedType - there is an ambiguity that needs 2 tokens of
	 * lookahead (SelectionType also starts with an identifier)
	 */
	readToken(token);
	parseType(token);
	return TRUE;
}

static boolean parseConstrainedSetOfType(tokenInfo *const token)
{
	if (!parseSizeConstraint(token) && !parseConstraint(token))
		return FALSE;

	return parseSetOfType(token);
}

static boolean parseSetXxxType(tokenInfo *const token)
{
	if (!isKeyword(token, KEYWORD_SET))
		return FALSE;

	readToken(token);
	if (!parseSetType(token) && !parseConstrainedSetOfType(token) &&
			!parseSetOfType(token))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected either:{, OF, (, SIZE, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	return TRUE;
}

static boolean parseTaggedType(tokenInfo *const token)
{
	if (!isType(token, TOKEN_PIPE))
		return FALSE;

	readToken(token);
	skipPastToken(token, TOKEN_PIPE); /* skip Class ClassNumber */

	if (isKeyword(token, KEYWORD_IMPLICIT) ||
			isKeyword(token, KEYWORD_EXPLICIT))
		readToken(token);

	parseType(token);
	return TRUE;
}

static boolean parseBuiltinType(tokenInfo *const token)
{
	return parseBitStringType(token) || parseBooleanType(token) ||
		parseCharacterStringType(token) || parseChoiceType(token) ||
		parseEmbeddedPDVType(token) || parseEnumeratedType(token) ||
		parseExternalType(token) || parseInstanceOfType(token) ||
		parseIntegerType(token) || parseIntegerType(token) ||
		parseNullType(token) || parseObjectClassFieldType(token) ||
		parseObjectIdentifierType(token) || parseOctetStringType(token) ||
		parseRealType(token) || parseRelativeOIDType(token) ||
		parseSequenceXxxType(token) || parseSetXxxType(token) ||
		parseTaggedType(token);
}

static boolean parseExternalTypeReferenceOrTypereference(tokenInfo *const token)
{
	if (!isType(token, TOKEN_UPPER_IDENTIFIER))
		return FALSE;

	readToken(token);
	if (isType(token, TOKEN_PERIOD))
	{
		readToken(token);
		if (!isType(token, TOKEN_UPPER_IDENTIFIER))
		{
			DebugStatement(debugPrintf(DEBUG_PARSE,
						"\n Parse Error in %s, expected typereference, got:%s\n",
						__FUNCTION__, vStringValue(token->string)));
			longjmp(Exception, ExceptionParseError);
		}

		readToken(token);
	}

	return TRUE;
}

static boolean parseParameterizedType(tokenInfo *const token)
{
	return FALSE; /* FIXME X.684 */
}

static boolean parseParameterizedValueSetType(tokenInfo *const token)
{
	return FALSE; /* FIXME X.684 */
}


static boolean parseDefinedType(tokenInfo *const token)
{
	return parseExternalTypeReferenceOrTypereference(token) ||
		parseParameterizedType(token) || parseParameterizedValueSetType(token);
}

static boolean parseUsefulType(tokenInfo *const token)
{
	if (!isKeywordAnyOf(token, KEYWORD_GeneralizedTime, KEYWORD_UTCTime,
			KEYWORD_ObjectDescriptor, KEYWORD_NONE))
		return FALSE;

	readToken(token);
	return TRUE;
}

static boolean parseSelectionType(tokenInfo *const token)
{
	if (!isType(token, TOKEN_LOWER_IDENTIFIER))
		return FALSE;

	readToken(token);
	if (!isType(token, TOKEN_ANGLE_BRACKET_OPEN))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:{, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	parseType(token);
	return TRUE;
}

static boolean parseTypeFromObject(tokenInfo *const token)
{
	return FALSE; /* FIXME X.681 */
}

static boolean parseValueSetFromObjects(tokenInfo *const token)
{
	return FALSE; /* FIXME X.681 */
}


static boolean parseReferencedType(tokenInfo *const token)
{
	return parseDefinedType(token) || parseUsefulType(token) ||
		parseSelectionType(token) || parseTypeFromObject(token) ||
		parseValueSetFromObjects(token);
}

static void parseType(tokenInfo *const token)
{
	if (!parseBuiltinType(token) && !parseReferencedType(token))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected to parse a type, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	parseConstraint(token);
}

static boolean parseTypeAssignment(tokenInfo *const token)
{
	if (!isType(token, TOKEN_UPPER_IDENTIFIER))
		return FALSE;

	addToScope(token, modulereference);
	makeAsnTag(token, K_TYPE);

	vStringCopy(identifier, token->string);

	readToken(token);
	if (!isType(token, TOKEN_ASSIGNMENT))
		return FALSE;

	readToken(token);
	parseType(token);

	return TRUE;
}

static boolean parseValueAssignment(tokenInfo *const token)
{
	if (!isType(token, TOKEN_LOWER_IDENTIFIER))
		return FALSE;

	return FALSE; /* FIXME */
}

static boolean parseAssignment(tokenInfo *const token)
{
	/* FIXME handle more than TypeAssignment and ValueAssignment */
	return parseTypeAssignment(token) || parseValueAssignment(token);
}

static void parseAssignmentList(tokenInfo *const token)
{
	while (parseAssignment(token)) {}
}

static void parseModuleBody(tokenInfo *const token)
{
	parseExports(token);
	parseImports(token);
	parseAssignmentList(token);
}

static boolean parseModuleDefinition(tokenInfo *const token)
{
	if (!isType(token, TOKEN_UPPER_IDENTIFIER))
		return FALSE;

	makeAsnTag(token, K_MODULE);

	vStringCopy(modulereference, token->string);

	readToken(token);
	skipPastKeyword(token, KEYWORD_DEFINITIONS); /* skip DefinitiveIdentifier */
	skipPastToken(token, TOKEN_ASSIGNMENT); /* skip TagDefault,ExtensionDefault */

	if (!isKeyword(token, KEYWORD_BEGIN))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:BEGIN, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);
	parseModuleBody(token);

	if (!isKeyword(token, KEYWORD_END))
	{
		DebugStatement(debugPrintf(DEBUG_PARSE,
					"\n Parse Error in %s, expected:END, got:%s\n",
					__FUNCTION__, vStringValue(token->string)));
		longjmp(Exception, ExceptionParseError);
	}

	readToken(token);

	return TRUE;
}

static void parseAsnFile(tokenInfo *const token)
{
	readToken(token);
	while (parseModuleDefinition(token)) {}
}

static void findAsnTags(void)
{
	exception_t exception;
	tokenInfo *const token = newToken();

	modulereference = vStringNew();
	identifier = vStringNew();

	exception = (exception_t) (setjmp(Exception));
	if (exception == ExceptionNone)
		parseAsnFile(token);

	vStringDelete(modulereference);
	vStringDelete(identifier);

	deleteToken(token);
}

static void buildAsnKeywordHash(void)
{
	const size_t count = sizeof(AsnKeywordTable) / sizeof(AsnKeywordTable[0]);
	size_t i;
	for (i = 0; i < count; ++i)
	{
		const keywordDesc *const p = &AsnKeywordTable[i];
		addKeyword(p->name, Lang_asn, p->id);
	}
}

static void initialize(const langType language)
{
	Lang_asn = language;
	buildAsnKeywordHash();
}

parserDefinition* AsnParser(void)
{
	static const char *const extensions[] = { "asn", "asn1", "ASN", "ASN1" ,
		"Asn", "Asn1", NULL };
	parserDefinition *def = parserNew("ASN.1");
	def->kinds		= AsnKinds;
	def->kindCount	= KIND_COUNT(AsnKinds);
	def->extensions = extensions;
	def->parser		= findAsnTags;
	def->initialize = initialize;

	return def;
}

/* vi:set tabstop=4 shiftwidth=4 noexpandtab: */
