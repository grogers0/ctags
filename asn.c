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

typedef enum eException { ExceptionNone, ExceptionEOF } exception_t;

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
	TOKEN_ASSIGNMENT,
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

static boolean isnewline(const int c)
{
	return c == '\n' || c == '\r' || c == '\v' || c == '\f';
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
	vStringClear (token->string);

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
		case EOF: longjmp(Exception, ExceptionEOF);		break;
		case '{': token->type = TOKEN_BRACE_OPEN;		break;
		case '}': token->type = TOKEN_BRACE_CLOSE;		break;
		case '(': token->type = TOKEN_PAREN_OPEN;		break;
		case ')': token->type = TOKEN_PAREN_CLOSE;		break;
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

void skipToToken(tokenInfo *const token, tokenType type)
{
	do
	{
		readToken(token);
	}
	while (!isType(token, type));
}

void skipToKeyword(tokenInfo *const token, keywordId keyword)
{
	do
	{
		readToken(token);
	}
	while (!isKeyword(token, keyword));
}

void addScopeQualifier(vString *const string)
{
	vStringCatS(string, ".");
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

void parseModuleDefinition(tokenInfo *const token)
{
	readToken(token);
	if (!isType(token, TOKEN_UPPER_IDENTIFIER))
		return;

	makeAsnTag(token, K_MODULE);

	vStringCopy(modulereference, token->string);

	skipToKeyword(token, KEYWORD_DEFINITIONS); /* skip DefinitiveIdentifier */
	skipToToken(token, TOKEN_ASSIGNMENT); /* skip TagDefault ExtensionDefault */

	readToken(token);
	if (!isKeyword(token, KEYWORD_BEGIN))
		return;

	/* parse ModuleBody */

	skipToKeyword(token, KEYWORD_END);
}

static void parseAsnFile(tokenInfo *const token)
{
	while (TRUE)
	{
		parseModuleDefinition(token);
	}
}

static void findAsnTags(void)
{
	exception_t exception;
	tokenInfo *const token = newToken();

	modulereference = vStringNew();

	exception = (exception_t) (setjmp(Exception));
	if (exception == ExceptionNone)
		parseAsnFile(token);

	vStringDelete(modulereference);

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
