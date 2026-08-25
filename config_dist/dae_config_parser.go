// Code generated from java-escape by ANTLR 4.11.1. DO NOT EDIT.

package dae_config // dae_config
import (
	"fmt"
	"strconv"
	"sync"

	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = strconv.Itoa
var _ = sync.Once{}

type dae_configParser struct {
	*antlr.BaseParser
}

var dae_configParserStaticData struct {
	once          sync.Once
	serializedATN []int32
	literalNames  []string
	symbolicNames []string
	ruleNames     []string
	atn           *antlr.ATN
}

func dae_configParserInit() {
	staticData := &dae_configParserStaticData
	staticData.literalNames = []string{
		"", "','", "'{'", "'}'", "':'", "'['", "']'", "'!'", "'('", "')'", "'->'",
		"'&&'",
	}
	staticData.symbolicNames = []string{
		"", "", "", "", "", "", "", "", "", "", "", "", "WHITESPACE", "COMMENT_BLOCK",
		"COMMENT_LINE_SHARP", "ID", "NON_ID", "QUOTE_STRING",
	}
	staticData.ruleNames = []string{
		"start", "bare_literal", "quote_literal", "literal", "literalExpression",
		"input", "programStructureBlcok", "expression", "declaration", "optAnnotation",
		"functionPrototype", "optParameterList", "nonEmptyParameterList", "parameter",
		"routingRule", "outboundExpr", "functionPrototypeExpression", "routingRuleOrDeclarationOrLiteralOrExpressionList",
		"routingRuleList",
	}
	staticData.serializedATN = []int32{
		4, 1, 17, 160, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2, 4, 7,
		4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 2, 10, 7,
		10, 2, 11, 7, 11, 2, 12, 7, 12, 2, 13, 7, 13, 2, 14, 7, 14, 2, 15, 7, 15,
		2, 16, 7, 16, 2, 17, 7, 17, 2, 18, 7, 18, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1,
		1, 2, 1, 2, 1, 3, 1, 3, 3, 3, 48, 8, 3, 1, 4, 1, 4, 1, 4, 1, 4, 1, 4, 3,
		4, 55, 8, 4, 1, 5, 1, 5, 1, 5, 3, 5, 60, 8, 5, 1, 5, 1, 5, 5, 5, 64, 8,
		5, 10, 5, 12, 5, 67, 9, 5, 1, 6, 1, 6, 1, 7, 1, 7, 1, 7, 1, 7, 1, 7, 1,
		8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 1, 8, 3, 8, 86, 8, 8,
		1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 3, 9, 93, 8, 9, 1, 10, 3, 10, 96, 8, 10,
		1, 10, 1, 10, 1, 10, 1, 10, 1, 10, 1, 11, 1, 11, 3, 11, 105, 8, 11, 1,
		12, 1, 12, 1, 12, 1, 12, 1, 12, 1, 12, 5, 12, 113, 8, 12, 10, 12, 12, 12,
		116, 9, 12, 1, 13, 1, 13, 1, 13, 1, 13, 3, 13, 122, 8, 13, 1, 14, 1, 14,
		1, 14, 1, 14, 1, 15, 1, 15, 3, 15, 130, 8, 15, 1, 16, 1, 16, 1, 16, 1,
		16, 1, 16, 3, 16, 137, 8, 16, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17,
		1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 1, 17, 3, 17, 152, 8, 17, 1,
		18, 1, 18, 1, 18, 1, 18, 3, 18, 158, 8, 18, 1, 18, 0, 2, 10, 24, 19, 0,
		2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 0,
		1, 1, 0, 15, 16, 157, 0, 38, 1, 0, 0, 0, 2, 41, 1, 0, 0, 0, 4, 43, 1, 0,
		0, 0, 6, 47, 1, 0, 0, 0, 8, 54, 1, 0, 0, 0, 10, 59, 1, 0, 0, 0, 12, 68,
		1, 0, 0, 0, 14, 70, 1, 0, 0, 0, 16, 85, 1, 0, 0, 0, 18, 92, 1, 0, 0, 0,
		20, 95, 1, 0, 0, 0, 22, 104, 1, 0, 0, 0, 24, 106, 1, 0, 0, 0, 26, 121,
		1, 0, 0, 0, 28, 123, 1, 0, 0, 0, 30, 129, 1, 0, 0, 0, 32, 136, 1, 0, 0,
		0, 34, 151, 1, 0, 0, 0, 36, 157, 1, 0, 0, 0, 38, 39, 3, 10, 5, 0, 39, 40,
		5, 0, 0, 1, 40, 1, 1, 0, 0, 0, 41, 42, 7, 0, 0, 0, 42, 3, 1, 0, 0, 0, 43,
		44, 5, 17, 0, 0, 44, 5, 1, 0, 0, 0, 45, 48, 3, 4, 2, 0, 46, 48, 3, 2, 1,
		0, 47, 45, 1, 0, 0, 0, 47, 46, 1, 0, 0, 0, 48, 7, 1, 0, 0, 0, 49, 50, 3,
		6, 3, 0, 50, 51, 5, 1, 0, 0, 51, 52, 3, 8, 4, 0, 52, 55, 1, 0, 0, 0, 53,
		55, 3, 6, 3, 0, 54, 49, 1, 0, 0, 0, 54, 53, 1, 0, 0, 0, 55, 9, 1, 0, 0,
		0, 56, 57, 6, 5, -1, 0, 57, 60, 3, 12, 6, 0, 58, 60, 1, 0, 0, 0, 59, 56,
		1, 0, 0, 0, 59, 58, 1, 0, 0, 0, 60, 65, 1, 0, 0, 0, 61, 62, 10, 2, 0, 0,
		62, 64, 3, 12, 6, 0, 63, 61, 1, 0, 0, 0, 64, 67, 1, 0, 0, 0, 65, 63, 1,
		0, 0, 0, 65, 66, 1, 0, 0, 0, 66, 11, 1, 0, 0, 0, 67, 65, 1, 0, 0, 0, 68,
		69, 3, 14, 7, 0, 69, 13, 1, 0, 0, 0, 70, 71, 5, 15, 0, 0, 71, 72, 5, 2,
		0, 0, 72, 73, 3, 34, 17, 0, 73, 74, 5, 3, 0, 0, 74, 15, 1, 0, 0, 0, 75,
		76, 5, 15, 0, 0, 76, 77, 5, 4, 0, 0, 77, 78, 3, 32, 16, 0, 78, 79, 3, 18,
		9, 0, 79, 86, 1, 0, 0, 0, 80, 81, 5, 15, 0, 0, 81, 82, 5, 4, 0, 0, 82,
		83, 3, 8, 4, 0, 83, 84, 3, 18, 9, 0, 84, 86, 1, 0, 0, 0, 85, 75, 1, 0,
		0, 0, 85, 80, 1, 0, 0, 0, 86, 17, 1, 0, 0, 0, 87, 88, 5, 5, 0, 0, 88, 89,
		3, 22, 11, 0, 89, 90, 5, 6, 0, 0, 90, 93, 1, 0, 0, 0, 91, 93, 1, 0, 0,
		0, 92, 87, 1, 0, 0, 0, 92, 91, 1, 0, 0, 0, 93, 19, 1, 0, 0, 0, 94, 96,
		5, 7, 0, 0, 95, 94, 1, 0, 0, 0, 95, 96, 1, 0, 0, 0, 96, 97, 1, 0, 0, 0,
		97, 98, 5, 15, 0, 0, 98, 99, 5, 8, 0, 0, 99, 100, 3, 22, 11, 0, 100, 101,
		5, 9, 0, 0, 101, 21, 1, 0, 0, 0, 102, 105, 3, 24, 12, 0, 103, 105, 1, 0,
		0, 0, 104, 102, 1, 0, 0, 0, 104, 103, 1, 0, 0, 0, 105, 23, 1, 0, 0, 0,
		106, 107, 6, 12, -1, 0, 107, 108, 3, 26, 13, 0, 108, 114, 1, 0, 0, 0, 109,
		110, 10, 1, 0, 0, 110, 111, 5, 1, 0, 0, 111, 113, 3, 26, 13, 0, 112, 109,
		1, 0, 0, 0, 113, 116, 1, 0, 0, 0, 114, 112, 1, 0, 0, 0, 114, 115, 1, 0,
		0, 0, 115, 25, 1, 0, 0, 0, 116, 114, 1, 0, 0, 0, 117, 118, 5, 15, 0, 0,
		118, 119, 5, 4, 0, 0, 119, 122, 3, 6, 3, 0, 120, 122, 3, 6, 3, 0, 121,
		117, 1, 0, 0, 0, 121, 120, 1, 0, 0, 0, 122, 27, 1, 0, 0, 0, 123, 124, 3,
		32, 16, 0, 124, 125, 5, 10, 0, 0, 125, 126, 3, 30, 15, 0, 126, 29, 1, 0,
		0, 0, 127, 130, 3, 2, 1, 0, 128, 130, 3, 20, 10, 0, 129, 127, 1, 0, 0,
		0, 129, 128, 1, 0, 0, 0, 130, 31, 1, 0, 0, 0, 131, 137, 3, 20, 10, 0, 132,
		133, 3, 20, 10, 0, 133, 134, 5, 11, 0, 0, 134, 135, 3, 32, 16, 0, 135,
		137, 1, 0, 0, 0, 136, 131, 1, 0, 0, 0, 136, 132, 1, 0, 0, 0, 137, 33, 1,
		0, 0, 0, 138, 139, 3, 28, 14, 0, 139, 140, 3, 34, 17, 0, 140, 152, 1, 0,
		0, 0, 141, 142, 3, 16, 8, 0, 142, 143, 3, 34, 17, 0, 143, 152, 1, 0, 0,
		0, 144, 145, 3, 6, 3, 0, 145, 146, 3, 34, 17, 0, 146, 152, 1, 0, 0, 0,
		147, 148, 3, 14, 7, 0, 148, 149, 3, 34, 17, 0, 149, 152, 1, 0, 0, 0, 150,
		152, 1, 0, 0, 0, 151, 138, 1, 0, 0, 0, 151, 141, 1, 0, 0, 0, 151, 144,
		1, 0, 0, 0, 151, 147, 1, 0, 0, 0, 151, 150, 1, 0, 0, 0, 152, 35, 1, 0,
		0, 0, 153, 158, 3, 28, 14, 0, 154, 155, 3, 28, 14, 0, 155, 156, 3, 36,
		18, 0, 156, 158, 1, 0, 0, 0, 157, 153, 1, 0, 0, 0, 157, 154, 1, 0, 0, 0,
		158, 37, 1, 0, 0, 0, 14, 47, 54, 59, 65, 85, 92, 95, 104, 114, 121, 129,
		136, 151, 157,
	}
	deserializer := antlr.NewATNDeserializer(nil)
	staticData.atn = deserializer.Deserialize(staticData.serializedATN)
}

// dae_configParserInit initializes any static state used to implement dae_configParser. By default the
// static state used to implement the parser is lazily initialized during the first call to
// Newdae_configParser(). You can call this function if you wish to initialize the static state ahead
// of time.
func Dae_configParserInit() {
	staticData := &dae_configParserStaticData
	staticData.once.Do(dae_configParserInit)
}

// freshDecisionToDFA allocates a per-parser DFA array so each parser instance
// owns its DFA cache and it can be reclaimed once the parser is discarded,
// instead of accumulating in package-level static state.
func freshDecisionToDFA(atn *antlr.ATN) []*antlr.DFA {
	decisionToDFA := make([]*antlr.DFA, len(atn.DecisionToState))
	for index, state := range atn.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(state, index)
	}
	return decisionToDFA
}

// Newdae_configParser produces a new parser instance for the optional input antlr.TokenStream.
func Newdae_configParser(input antlr.TokenStream) *dae_configParser {
	Dae_configParserInit()
	this := new(dae_configParser)
	this.BaseParser = antlr.NewBaseParser(input)
	staticData := &dae_configParserStaticData
	this.Interpreter = antlr.NewParserATNSimulator(this, staticData.atn, freshDecisionToDFA(staticData.atn), antlr.NewPredictionContextCache())
	this.RuleNames = staticData.ruleNames
	this.LiteralNames = staticData.literalNames
	this.SymbolicNames = staticData.symbolicNames
	this.GrammarFileName = "java-escape"

	return this
}

// dae_configParser tokens.
const (
	dae_configParserEOF                = antlr.TokenEOF
	dae_configParserT__0               = 1
	dae_configParserT__1               = 2
	dae_configParserT__2               = 3
	dae_configParserT__3               = 4
	dae_configParserT__4               = 5
	dae_configParserT__5               = 6
	dae_configParserT__6               = 7
	dae_configParserT__7               = 8
	dae_configParserT__8               = 9
	dae_configParserT__9               = 10
	dae_configParserT__10              = 11
	dae_configParserWHITESPACE         = 12
	dae_configParserCOMMENT_BLOCK      = 13
	dae_configParserCOMMENT_LINE_SHARP = 14
	dae_configParserID                 = 15
	dae_configParserNON_ID             = 16
	dae_configParserQUOTE_STRING       = 17
)

// dae_configParser rules.
const (
	dae_configParserRULE_start                                             = 0
	dae_configParserRULE_bare_literal                                      = 1
	dae_configParserRULE_quote_literal                                     = 2
	dae_configParserRULE_literal                                           = 3
	dae_configParserRULE_literalExpression                                 = 4
	dae_configParserRULE_input                                             = 5
	dae_configParserRULE_programStructureBlcok                             = 6
	dae_configParserRULE_expression                                        = 7
	dae_configParserRULE_declaration                                       = 8
	dae_configParserRULE_optAnnotation                                     = 9
	dae_configParserRULE_functionPrototype                                 = 10
	dae_configParserRULE_optParameterList                                  = 11
	dae_configParserRULE_nonEmptyParameterList                             = 12
	dae_configParserRULE_parameter                                         = 13
	dae_configParserRULE_routingRule                                       = 14
	dae_configParserRULE_outboundExpr                                      = 15
	dae_configParserRULE_functionPrototypeExpression                       = 16
	dae_configParserRULE_routingRuleOrDeclarationOrLiteralOrExpressionList = 17
	dae_configParserRULE_routingRuleList                                   = 18
)

// IStartContext is an interface to support dynamic dispatch.
type IStartContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsStartContext differentiates from other interfaces.
	IsStartContext()
}

type StartContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyStartContext() *StartContext {
	var p = new(StartContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_start
	return p
}

func (*StartContext) IsStartContext() {}

func NewStartContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *StartContext {
	var p = new(StartContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_start

	return p
}

func (s *StartContext) GetParser() antlr.Parser { return s.parser }

func (s *StartContext) Input() IInputContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IInputContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IInputContext)
}

func (s *StartContext) EOF() antlr.TerminalNode {
	return s.GetToken(dae_configParserEOF, 0)
}

func (s *StartContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StartContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *StartContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterStart(s)
	}
}

func (s *StartContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitStart(s)
	}
}

func (p *dae_configParser) Start() (localctx IStartContext) {
	this := p
	_ = this

	localctx = NewStartContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, dae_configParserRULE_start)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(38)
		p.input(0)
	}
	{
		p.SetState(39)
		p.Match(dae_configParserEOF)
	}

	return localctx
}

// IBare_literalContext is an interface to support dynamic dispatch.
type IBare_literalContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsBare_literalContext differentiates from other interfaces.
	IsBare_literalContext()
}

type Bare_literalContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyBare_literalContext() *Bare_literalContext {
	var p = new(Bare_literalContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_bare_literal
	return p
}

func (*Bare_literalContext) IsBare_literalContext() {}

func NewBare_literalContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *Bare_literalContext {
	var p = new(Bare_literalContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_bare_literal

	return p
}

func (s *Bare_literalContext) GetParser() antlr.Parser { return s.parser }

func (s *Bare_literalContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *Bare_literalContext) NON_ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserNON_ID, 0)
}

func (s *Bare_literalContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *Bare_literalContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *Bare_literalContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterBare_literal(s)
	}
}

func (s *Bare_literalContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitBare_literal(s)
	}
}

func (p *dae_configParser) Bare_literal() (localctx IBare_literalContext) {
	this := p
	_ = this

	localctx = NewBare_literalContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, dae_configParserRULE_bare_literal)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(41)
		_la = p.GetTokenStream().LA(1)

		if !(_la == dae_configParserID || _la == dae_configParserNON_ID) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// IQuote_literalContext is an interface to support dynamic dispatch.
type IQuote_literalContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsQuote_literalContext differentiates from other interfaces.
	IsQuote_literalContext()
}

type Quote_literalContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyQuote_literalContext() *Quote_literalContext {
	var p = new(Quote_literalContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_quote_literal
	return p
}

func (*Quote_literalContext) IsQuote_literalContext() {}

func NewQuote_literalContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *Quote_literalContext {
	var p = new(Quote_literalContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_quote_literal

	return p
}

func (s *Quote_literalContext) GetParser() antlr.Parser { return s.parser }

func (s *Quote_literalContext) QUOTE_STRING() antlr.TerminalNode {
	return s.GetToken(dae_configParserQUOTE_STRING, 0)
}

func (s *Quote_literalContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *Quote_literalContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *Quote_literalContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterQuote_literal(s)
	}
}

func (s *Quote_literalContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitQuote_literal(s)
	}
}

func (p *dae_configParser) Quote_literal() (localctx IQuote_literalContext) {
	this := p
	_ = this

	localctx = NewQuote_literalContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, dae_configParserRULE_quote_literal)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(43)
		p.Match(dae_configParserQUOTE_STRING)
	}

	return localctx
}

// ILiteralContext is an interface to support dynamic dispatch.
type ILiteralContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsLiteralContext differentiates from other interfaces.
	IsLiteralContext()
}

type LiteralContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyLiteralContext() *LiteralContext {
	var p = new(LiteralContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_literal
	return p
}

func (*LiteralContext) IsLiteralContext() {}

func NewLiteralContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *LiteralContext {
	var p = new(LiteralContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_literal

	return p
}

func (s *LiteralContext) GetParser() antlr.Parser { return s.parser }

func (s *LiteralContext) Quote_literal() IQuote_literalContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IQuote_literalContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IQuote_literalContext)
}

func (s *LiteralContext) Bare_literal() IBare_literalContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IBare_literalContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IBare_literalContext)
}

func (s *LiteralContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *LiteralContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *LiteralContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterLiteral(s)
	}
}

func (s *LiteralContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitLiteral(s)
	}
}

func (p *dae_configParser) Literal() (localctx ILiteralContext) {
	this := p
	_ = this

	localctx = NewLiteralContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, dae_configParserRULE_literal)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(47)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case dae_configParserQUOTE_STRING:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(45)
			p.Quote_literal()
		}

	case dae_configParserID, dae_configParserNON_ID:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(46)
			p.Bare_literal()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// ILiteralExpressionContext is an interface to support dynamic dispatch.
type ILiteralExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsLiteralExpressionContext differentiates from other interfaces.
	IsLiteralExpressionContext()
}

type LiteralExpressionContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyLiteralExpressionContext() *LiteralExpressionContext {
	var p = new(LiteralExpressionContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_literalExpression
	return p
}

func (*LiteralExpressionContext) IsLiteralExpressionContext() {}

func NewLiteralExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *LiteralExpressionContext {
	var p = new(LiteralExpressionContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_literalExpression

	return p
}

func (s *LiteralExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *LiteralExpressionContext) Literal() ILiteralContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *LiteralExpressionContext) LiteralExpression() ILiteralExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralExpressionContext)
}

func (s *LiteralExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *LiteralExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *LiteralExpressionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterLiteralExpression(s)
	}
}

func (s *LiteralExpressionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitLiteralExpression(s)
	}
}

func (p *dae_configParser) LiteralExpression() (localctx ILiteralExpressionContext) {
	this := p
	_ = this

	localctx = NewLiteralExpressionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, dae_configParserRULE_literalExpression)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(54)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 1, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(49)
			p.Literal()
		}
		{
			p.SetState(50)
			p.Match(dae_configParserT__0)
		}
		{
			p.SetState(51)
			p.LiteralExpression()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(53)
			p.Literal()
		}

	}

	return localctx
}

// IInputContext is an interface to support dynamic dispatch.
type IInputContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsInputContext differentiates from other interfaces.
	IsInputContext()
}

type InputContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyInputContext() *InputContext {
	var p = new(InputContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_input
	return p
}

func (*InputContext) IsInputContext() {}

func NewInputContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *InputContext {
	var p = new(InputContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_input

	return p
}

func (s *InputContext) GetParser() antlr.Parser { return s.parser }

func (s *InputContext) ProgramStructureBlcok() IProgramStructureBlcokContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IProgramStructureBlcokContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IProgramStructureBlcokContext)
}

func (s *InputContext) Input() IInputContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IInputContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IInputContext)
}

func (s *InputContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *InputContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *InputContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterInput(s)
	}
}

func (s *InputContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitInput(s)
	}
}

func (p *dae_configParser) Input() (localctx IInputContext) {
	return p.input(0)
}

func (p *dae_configParser) input(_p int) (localctx IInputContext) {
	this := p
	_ = this

	var _parentctx antlr.ParserRuleContext = p.GetParserRuleContext()
	_parentState := p.GetState()
	localctx = NewInputContext(p, p.GetParserRuleContext(), _parentState)
	var _prevctx IInputContext = localctx
	var _ antlr.ParserRuleContext = _prevctx // TODO: To prevent unused variable warning.
	_startState := 10
	p.EnterRecursionRule(localctx, 10, dae_configParserRULE_input, _p)

	defer func() {
		p.UnrollRecursionContexts(_parentctx)
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(59)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 2, p.GetParserRuleContext()) {
	case 1:
		{
			p.SetState(57)
			p.ProgramStructureBlcok()
		}

	case 2:

	}
	p.GetParserRuleContext().SetStop(p.GetTokenStream().LT(-1))
	p.SetState(65)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 3, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			if p.GetParseListeners() != nil {
				p.TriggerExitRuleEvent()
			}
			_prevctx = localctx
			localctx = NewInputContext(p, _parentctx, _parentState)
			p.PushNewRecursionContext(localctx, _startState, dae_configParserRULE_input)
			p.SetState(61)

			if !(p.Precpred(p.GetParserRuleContext(), 2)) {
				panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 2)", ""))
			}
			{
				p.SetState(62)
				p.ProgramStructureBlcok()
			}

		}
		p.SetState(67)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 3, p.GetParserRuleContext())
	}

	return localctx
}

// IProgramStructureBlcokContext is an interface to support dynamic dispatch.
type IProgramStructureBlcokContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsProgramStructureBlcokContext differentiates from other interfaces.
	IsProgramStructureBlcokContext()
}

type ProgramStructureBlcokContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyProgramStructureBlcokContext() *ProgramStructureBlcokContext {
	var p = new(ProgramStructureBlcokContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_programStructureBlcok
	return p
}

func (*ProgramStructureBlcokContext) IsProgramStructureBlcokContext() {}

func NewProgramStructureBlcokContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ProgramStructureBlcokContext {
	var p = new(ProgramStructureBlcokContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_programStructureBlcok

	return p
}

func (s *ProgramStructureBlcokContext) GetParser() antlr.Parser { return s.parser }

func (s *ProgramStructureBlcokContext) Expression() IExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *ProgramStructureBlcokContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ProgramStructureBlcokContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ProgramStructureBlcokContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterProgramStructureBlcok(s)
	}
}

func (s *ProgramStructureBlcokContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitProgramStructureBlcok(s)
	}
}

func (p *dae_configParser) ProgramStructureBlcok() (localctx IProgramStructureBlcokContext) {
	this := p
	_ = this

	localctx = NewProgramStructureBlcokContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, dae_configParserRULE_programStructureBlcok)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(68)
		p.Expression()
	}

	return localctx
}

// IExpressionContext is an interface to support dynamic dispatch.
type IExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsExpressionContext differentiates from other interfaces.
	IsExpressionContext()
}

type ExpressionContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyExpressionContext() *ExpressionContext {
	var p = new(ExpressionContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_expression
	return p
}

func (*ExpressionContext) IsExpressionContext() {}

func NewExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ExpressionContext {
	var p = new(ExpressionContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_expression

	return p
}

func (s *ExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *ExpressionContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *ExpressionContext) RoutingRuleOrDeclarationOrLiteralOrExpressionList() IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext)
}

func (s *ExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ExpressionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterExpression(s)
	}
}

func (s *ExpressionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitExpression(s)
	}
}

func (p *dae_configParser) Expression() (localctx IExpressionContext) {
	this := p
	_ = this

	localctx = NewExpressionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, dae_configParserRULE_expression)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(70)
		p.Match(dae_configParserID)
	}
	{
		p.SetState(71)
		p.Match(dae_configParserT__1)
	}
	{
		p.SetState(72)
		p.RoutingRuleOrDeclarationOrLiteralOrExpressionList()
	}
	{
		p.SetState(73)
		p.Match(dae_configParserT__2)
	}

	return localctx
}

// IDeclarationContext is an interface to support dynamic dispatch.
type IDeclarationContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsDeclarationContext differentiates from other interfaces.
	IsDeclarationContext()
}

type DeclarationContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyDeclarationContext() *DeclarationContext {
	var p = new(DeclarationContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_declaration
	return p
}

func (*DeclarationContext) IsDeclarationContext() {}

func NewDeclarationContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *DeclarationContext {
	var p = new(DeclarationContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_declaration

	return p
}

func (s *DeclarationContext) GetParser() antlr.Parser { return s.parser }

func (s *DeclarationContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *DeclarationContext) FunctionPrototypeExpression() IFunctionPrototypeExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeExpressionContext)
}

func (s *DeclarationContext) OptAnnotation() IOptAnnotationContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOptAnnotationContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOptAnnotationContext)
}

func (s *DeclarationContext) LiteralExpression() ILiteralExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralExpressionContext)
}

func (s *DeclarationContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *DeclarationContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *DeclarationContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterDeclaration(s)
	}
}

func (s *DeclarationContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitDeclaration(s)
	}
}

func (p *dae_configParser) Declaration() (localctx IDeclarationContext) {
	this := p
	_ = this

	localctx = NewDeclarationContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 16, dae_configParserRULE_declaration)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(85)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 4, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(75)
			p.Match(dae_configParserID)
		}
		{
			p.SetState(76)
			p.Match(dae_configParserT__3)
		}
		{
			p.SetState(77)
			p.FunctionPrototypeExpression()
		}
		{
			p.SetState(78)
			p.OptAnnotation()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(80)
			p.Match(dae_configParserID)
		}
		{
			p.SetState(81)
			p.Match(dae_configParserT__3)
		}
		{
			p.SetState(82)
			p.LiteralExpression()
		}
		{
			p.SetState(83)
			p.OptAnnotation()
		}

	}

	return localctx
}

// IOptAnnotationContext is an interface to support dynamic dispatch.
type IOptAnnotationContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsOptAnnotationContext differentiates from other interfaces.
	IsOptAnnotationContext()
}

type OptAnnotationContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyOptAnnotationContext() *OptAnnotationContext {
	var p = new(OptAnnotationContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_optAnnotation
	return p
}

func (*OptAnnotationContext) IsOptAnnotationContext() {}

func NewOptAnnotationContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *OptAnnotationContext {
	var p = new(OptAnnotationContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_optAnnotation

	return p
}

func (s *OptAnnotationContext) GetParser() antlr.Parser { return s.parser }

func (s *OptAnnotationContext) OptParameterList() IOptParameterListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOptParameterListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOptParameterListContext)
}

func (s *OptAnnotationContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OptAnnotationContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *OptAnnotationContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterOptAnnotation(s)
	}
}

func (s *OptAnnotationContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitOptAnnotation(s)
	}
}

func (p *dae_configParser) OptAnnotation() (localctx IOptAnnotationContext) {
	this := p
	_ = this

	localctx = NewOptAnnotationContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 18, dae_configParserRULE_optAnnotation)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(92)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case dae_configParserT__4:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(87)
			p.Match(dae_configParserT__4)
		}
		{
			p.SetState(88)
			p.OptParameterList()
		}
		{
			p.SetState(89)
			p.Match(dae_configParserT__5)
		}

	case dae_configParserT__2, dae_configParserT__6, dae_configParserID, dae_configParserNON_ID, dae_configParserQUOTE_STRING:
		p.EnterOuterAlt(localctx, 2)

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IFunctionPrototypeContext is an interface to support dynamic dispatch.
type IFunctionPrototypeContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsFunctionPrototypeContext differentiates from other interfaces.
	IsFunctionPrototypeContext()
}

type FunctionPrototypeContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyFunctionPrototypeContext() *FunctionPrototypeContext {
	var p = new(FunctionPrototypeContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_functionPrototype
	return p
}

func (*FunctionPrototypeContext) IsFunctionPrototypeContext() {}

func NewFunctionPrototypeContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FunctionPrototypeContext {
	var p = new(FunctionPrototypeContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_functionPrototype

	return p
}

func (s *FunctionPrototypeContext) GetParser() antlr.Parser { return s.parser }

func (s *FunctionPrototypeContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *FunctionPrototypeContext) OptParameterList() IOptParameterListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOptParameterListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOptParameterListContext)
}

func (s *FunctionPrototypeContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FunctionPrototypeContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FunctionPrototypeContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterFunctionPrototype(s)
	}
}

func (s *FunctionPrototypeContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitFunctionPrototype(s)
	}
}

func (p *dae_configParser) FunctionPrototype() (localctx IFunctionPrototypeContext) {
	this := p
	_ = this

	localctx = NewFunctionPrototypeContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 20, dae_configParserRULE_functionPrototype)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(95)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	if _la == dae_configParserT__6 {
		{
			p.SetState(94)
			p.Match(dae_configParserT__6)
		}

	}
	{
		p.SetState(97)
		p.Match(dae_configParserID)
	}
	{
		p.SetState(98)
		p.Match(dae_configParserT__7)
	}
	{
		p.SetState(99)
		p.OptParameterList()
	}
	{
		p.SetState(100)
		p.Match(dae_configParserT__8)
	}

	return localctx
}

// IOptParameterListContext is an interface to support dynamic dispatch.
type IOptParameterListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsOptParameterListContext differentiates from other interfaces.
	IsOptParameterListContext()
}

type OptParameterListContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyOptParameterListContext() *OptParameterListContext {
	var p = new(OptParameterListContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_optParameterList
	return p
}

func (*OptParameterListContext) IsOptParameterListContext() {}

func NewOptParameterListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *OptParameterListContext {
	var p = new(OptParameterListContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_optParameterList

	return p
}

func (s *OptParameterListContext) GetParser() antlr.Parser { return s.parser }

func (s *OptParameterListContext) NonEmptyParameterList() INonEmptyParameterListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(INonEmptyParameterListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(INonEmptyParameterListContext)
}

func (s *OptParameterListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OptParameterListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *OptParameterListContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterOptParameterList(s)
	}
}

func (s *OptParameterListContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitOptParameterList(s)
	}
}

func (p *dae_configParser) OptParameterList() (localctx IOptParameterListContext) {
	this := p
	_ = this

	localctx = NewOptParameterListContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 22, dae_configParserRULE_optParameterList)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(104)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case dae_configParserID, dae_configParserNON_ID, dae_configParserQUOTE_STRING:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(102)
			p.nonEmptyParameterList(0)
		}

	case dae_configParserT__5, dae_configParserT__8:
		p.EnterOuterAlt(localctx, 2)

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// INonEmptyParameterListContext is an interface to support dynamic dispatch.
type INonEmptyParameterListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsNonEmptyParameterListContext differentiates from other interfaces.
	IsNonEmptyParameterListContext()
}

type NonEmptyParameterListContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyNonEmptyParameterListContext() *NonEmptyParameterListContext {
	var p = new(NonEmptyParameterListContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_nonEmptyParameterList
	return p
}

func (*NonEmptyParameterListContext) IsNonEmptyParameterListContext() {}

func NewNonEmptyParameterListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *NonEmptyParameterListContext {
	var p = new(NonEmptyParameterListContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_nonEmptyParameterList

	return p
}

func (s *NonEmptyParameterListContext) GetParser() antlr.Parser { return s.parser }

func (s *NonEmptyParameterListContext) Parameter() IParameterContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IParameterContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IParameterContext)
}

func (s *NonEmptyParameterListContext) NonEmptyParameterList() INonEmptyParameterListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(INonEmptyParameterListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(INonEmptyParameterListContext)
}

func (s *NonEmptyParameterListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *NonEmptyParameterListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *NonEmptyParameterListContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterNonEmptyParameterList(s)
	}
}

func (s *NonEmptyParameterListContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitNonEmptyParameterList(s)
	}
}

func (p *dae_configParser) NonEmptyParameterList() (localctx INonEmptyParameterListContext) {
	return p.nonEmptyParameterList(0)
}

func (p *dae_configParser) nonEmptyParameterList(_p int) (localctx INonEmptyParameterListContext) {
	this := p
	_ = this

	var _parentctx antlr.ParserRuleContext = p.GetParserRuleContext()
	_parentState := p.GetState()
	localctx = NewNonEmptyParameterListContext(p, p.GetParserRuleContext(), _parentState)
	var _prevctx INonEmptyParameterListContext = localctx
	var _ antlr.ParserRuleContext = _prevctx // TODO: To prevent unused variable warning.
	_startState := 24
	p.EnterRecursionRule(localctx, 24, dae_configParserRULE_nonEmptyParameterList, _p)

	defer func() {
		p.UnrollRecursionContexts(_parentctx)
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(107)
		p.Parameter()
	}

	p.GetParserRuleContext().SetStop(p.GetTokenStream().LT(-1))
	p.SetState(114)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 8, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			if p.GetParseListeners() != nil {
				p.TriggerExitRuleEvent()
			}
			_prevctx = localctx
			localctx = NewNonEmptyParameterListContext(p, _parentctx, _parentState)
			p.PushNewRecursionContext(localctx, _startState, dae_configParserRULE_nonEmptyParameterList)
			p.SetState(109)

			if !(p.Precpred(p.GetParserRuleContext(), 1)) {
				panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 1)", ""))
			}
			{
				p.SetState(110)
				p.Match(dae_configParserT__0)
			}
			{
				p.SetState(111)
				p.Parameter()
			}

		}
		p.SetState(116)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 8, p.GetParserRuleContext())
	}

	return localctx
}

// IParameterContext is an interface to support dynamic dispatch.
type IParameterContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsParameterContext differentiates from other interfaces.
	IsParameterContext()
}

type ParameterContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyParameterContext() *ParameterContext {
	var p = new(ParameterContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_parameter
	return p
}

func (*ParameterContext) IsParameterContext() {}

func NewParameterContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ParameterContext {
	var p = new(ParameterContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_parameter

	return p
}

func (s *ParameterContext) GetParser() antlr.Parser { return s.parser }

func (s *ParameterContext) ID() antlr.TerminalNode {
	return s.GetToken(dae_configParserID, 0)
}

func (s *ParameterContext) Literal() ILiteralContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *ParameterContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ParameterContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ParameterContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterParameter(s)
	}
}

func (s *ParameterContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitParameter(s)
	}
}

func (p *dae_configParser) Parameter() (localctx IParameterContext) {
	this := p
	_ = this

	localctx = NewParameterContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 26, dae_configParserRULE_parameter)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(121)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 9, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(117)
			p.Match(dae_configParserID)
		}
		{
			p.SetState(118)
			p.Match(dae_configParserT__3)
		}
		{
			p.SetState(119)
			p.Literal()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(120)
			p.Literal()
		}

	}

	return localctx
}

// IRoutingRuleContext is an interface to support dynamic dispatch.
type IRoutingRuleContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsRoutingRuleContext differentiates from other interfaces.
	IsRoutingRuleContext()
}

type RoutingRuleContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyRoutingRuleContext() *RoutingRuleContext {
	var p = new(RoutingRuleContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_routingRule
	return p
}

func (*RoutingRuleContext) IsRoutingRuleContext() {}

func NewRoutingRuleContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *RoutingRuleContext {
	var p = new(RoutingRuleContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_routingRule

	return p
}

func (s *RoutingRuleContext) GetParser() antlr.Parser { return s.parser }

func (s *RoutingRuleContext) FunctionPrototypeExpression() IFunctionPrototypeExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeExpressionContext)
}

func (s *RoutingRuleContext) OutboundExpr() IOutboundExprContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IOutboundExprContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IOutboundExprContext)
}

func (s *RoutingRuleContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *RoutingRuleContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *RoutingRuleContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterRoutingRule(s)
	}
}

func (s *RoutingRuleContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitRoutingRule(s)
	}
}

func (p *dae_configParser) RoutingRule() (localctx IRoutingRuleContext) {
	this := p
	_ = this

	localctx = NewRoutingRuleContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 28, dae_configParserRULE_routingRule)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(123)
		p.FunctionPrototypeExpression()
	}
	{
		p.SetState(124)
		p.Match(dae_configParserT__9)
	}
	{
		p.SetState(125)
		p.OutboundExpr()
	}

	return localctx
}

// IOutboundExprContext is an interface to support dynamic dispatch.
type IOutboundExprContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsOutboundExprContext differentiates from other interfaces.
	IsOutboundExprContext()
}

type OutboundExprContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyOutboundExprContext() *OutboundExprContext {
	var p = new(OutboundExprContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_outboundExpr
	return p
}

func (*OutboundExprContext) IsOutboundExprContext() {}

func NewOutboundExprContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *OutboundExprContext {
	var p = new(OutboundExprContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_outboundExpr

	return p
}

func (s *OutboundExprContext) GetParser() antlr.Parser { return s.parser }

func (s *OutboundExprContext) Bare_literal() IBare_literalContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IBare_literalContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IBare_literalContext)
}

func (s *OutboundExprContext) FunctionPrototype() IFunctionPrototypeContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeContext)
}

func (s *OutboundExprContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OutboundExprContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *OutboundExprContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterOutboundExpr(s)
	}
}

func (s *OutboundExprContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitOutboundExpr(s)
	}
}

func (p *dae_configParser) OutboundExpr() (localctx IOutboundExprContext) {
	this := p
	_ = this

	localctx = NewOutboundExprContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 30, dae_configParserRULE_outboundExpr)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(129)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 10, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(127)
			p.Bare_literal()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(128)
			p.FunctionPrototype()
		}

	}

	return localctx
}

// IFunctionPrototypeExpressionContext is an interface to support dynamic dispatch.
type IFunctionPrototypeExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsFunctionPrototypeExpressionContext differentiates from other interfaces.
	IsFunctionPrototypeExpressionContext()
}

type FunctionPrototypeExpressionContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyFunctionPrototypeExpressionContext() *FunctionPrototypeExpressionContext {
	var p = new(FunctionPrototypeExpressionContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_functionPrototypeExpression
	return p
}

func (*FunctionPrototypeExpressionContext) IsFunctionPrototypeExpressionContext() {}

func NewFunctionPrototypeExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FunctionPrototypeExpressionContext {
	var p = new(FunctionPrototypeExpressionContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_functionPrototypeExpression

	return p
}

func (s *FunctionPrototypeExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *FunctionPrototypeExpressionContext) FunctionPrototype() IFunctionPrototypeContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeContext)
}

func (s *FunctionPrototypeExpressionContext) FunctionPrototypeExpression() IFunctionPrototypeExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IFunctionPrototypeExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IFunctionPrototypeExpressionContext)
}

func (s *FunctionPrototypeExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FunctionPrototypeExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FunctionPrototypeExpressionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterFunctionPrototypeExpression(s)
	}
}

func (s *FunctionPrototypeExpressionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitFunctionPrototypeExpression(s)
	}
}

func (p *dae_configParser) FunctionPrototypeExpression() (localctx IFunctionPrototypeExpressionContext) {
	this := p
	_ = this

	localctx = NewFunctionPrototypeExpressionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 32, dae_configParserRULE_functionPrototypeExpression)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(136)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 11, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(131)
			p.FunctionPrototype()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(132)
			p.FunctionPrototype()
		}
		{
			p.SetState(133)
			p.Match(dae_configParserT__10)
		}
		{
			p.SetState(134)
			p.FunctionPrototypeExpression()
		}

	}

	return localctx
}

// IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext is an interface to support dynamic dispatch.
type IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsRoutingRuleOrDeclarationOrLiteralOrExpressionListContext differentiates from other interfaces.
	IsRoutingRuleOrDeclarationOrLiteralOrExpressionListContext()
}

type RoutingRuleOrDeclarationOrLiteralOrExpressionListContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyRoutingRuleOrDeclarationOrLiteralOrExpressionListContext() *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext {
	var p = new(RoutingRuleOrDeclarationOrLiteralOrExpressionListContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_routingRuleOrDeclarationOrLiteralOrExpressionList
	return p
}

func (*RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) IsRoutingRuleOrDeclarationOrLiteralOrExpressionListContext() {
}

func NewRoutingRuleOrDeclarationOrLiteralOrExpressionListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext {
	var p = new(RoutingRuleOrDeclarationOrLiteralOrExpressionListContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_routingRuleOrDeclarationOrLiteralOrExpressionList

	return p
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) GetParser() antlr.Parser {
	return s.parser
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) RoutingRule() IRoutingRuleContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IRoutingRuleContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IRoutingRuleContext)
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) RoutingRuleOrDeclarationOrLiteralOrExpressionList() IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext)
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) Declaration() IDeclarationContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IDeclarationContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IDeclarationContext)
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) Literal() ILiteralContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ILiteralContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ILiteralContext)
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) Expression() IExpressionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IExpressionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterRoutingRuleOrDeclarationOrLiteralOrExpressionList(s)
	}
}

func (s *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitRoutingRuleOrDeclarationOrLiteralOrExpressionList(s)
	}
}

func (p *dae_configParser) RoutingRuleOrDeclarationOrLiteralOrExpressionList() (localctx IRoutingRuleOrDeclarationOrLiteralOrExpressionListContext) {
	this := p
	_ = this

	localctx = NewRoutingRuleOrDeclarationOrLiteralOrExpressionListContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 34, dae_configParserRULE_routingRuleOrDeclarationOrLiteralOrExpressionList)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(151)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 12, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(138)
			p.RoutingRule()
		}
		{
			p.SetState(139)
			p.RoutingRuleOrDeclarationOrLiteralOrExpressionList()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(141)
			p.Declaration()
		}
		{
			p.SetState(142)
			p.RoutingRuleOrDeclarationOrLiteralOrExpressionList()
		}

	case 3:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(144)
			p.Literal()
		}
		{
			p.SetState(145)
			p.RoutingRuleOrDeclarationOrLiteralOrExpressionList()
		}

	case 4:
		p.EnterOuterAlt(localctx, 4)
		{
			p.SetState(147)
			p.Expression()
		}
		{
			p.SetState(148)
			p.RoutingRuleOrDeclarationOrLiteralOrExpressionList()
		}

	case 5:
		p.EnterOuterAlt(localctx, 5)

	}

	return localctx
}

// IRoutingRuleListContext is an interface to support dynamic dispatch.
type IRoutingRuleListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsRoutingRuleListContext differentiates from other interfaces.
	IsRoutingRuleListContext()
}

type RoutingRuleListContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyRoutingRuleListContext() *RoutingRuleListContext {
	var p = new(RoutingRuleListContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = dae_configParserRULE_routingRuleList
	return p
}

func (*RoutingRuleListContext) IsRoutingRuleListContext() {}

func NewRoutingRuleListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *RoutingRuleListContext {
	var p = new(RoutingRuleListContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = dae_configParserRULE_routingRuleList

	return p
}

func (s *RoutingRuleListContext) GetParser() antlr.Parser { return s.parser }

func (s *RoutingRuleListContext) RoutingRule() IRoutingRuleContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IRoutingRuleContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IRoutingRuleContext)
}

func (s *RoutingRuleListContext) RoutingRuleList() IRoutingRuleListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IRoutingRuleListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IRoutingRuleListContext)
}

func (s *RoutingRuleListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *RoutingRuleListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *RoutingRuleListContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.EnterRoutingRuleList(s)
	}
}

func (s *RoutingRuleListContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(dae_configListener); ok {
		listenerT.ExitRoutingRuleList(s)
	}
}

func (p *dae_configParser) RoutingRuleList() (localctx IRoutingRuleListContext) {
	this := p
	_ = this

	localctx = NewRoutingRuleListContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 36, dae_configParserRULE_routingRuleList)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(157)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 13, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(153)
			p.RoutingRule()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(154)
			p.RoutingRule()
		}
		{
			p.SetState(155)
			p.RoutingRuleList()
		}

	}

	return localctx
}

func (p *dae_configParser) Sempred(localctx antlr.RuleContext, ruleIndex, predIndex int) bool {
	switch ruleIndex {
	case 5:
		var t *InputContext = nil
		if localctx != nil {
			t = localctx.(*InputContext)
		}
		return p.Input_Sempred(t, predIndex)

	case 12:
		var t *NonEmptyParameterListContext = nil
		if localctx != nil {
			t = localctx.(*NonEmptyParameterListContext)
		}
		return p.NonEmptyParameterList_Sempred(t, predIndex)

	default:
		panic("No predicate with index: " + fmt.Sprint(ruleIndex))
	}
}

func (p *dae_configParser) Input_Sempred(localctx antlr.RuleContext, predIndex int) bool {
	this := p
	_ = this

	switch predIndex {
	case 0:
		return p.Precpred(p.GetParserRuleContext(), 2)

	default:
		panic("No predicate with index: " + fmt.Sprint(predIndex))
	}
}

func (p *dae_configParser) NonEmptyParameterList_Sempred(localctx antlr.RuleContext, predIndex int) bool {
	this := p
	_ = this

	switch predIndex {
	case 1:
		return p.Precpred(p.GetParserRuleContext(), 1)

	default:
		panic("No predicate with index: " + fmt.Sprint(predIndex))
	}
}
