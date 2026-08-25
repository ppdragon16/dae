// Code generated from java-escape by ANTLR 4.11.1. DO NOT EDIT.

package dae_config // dae_config
import "github.com/antlr/antlr4/runtime/Go/antlr/v4"

// dae_configListener is a complete listener for a parse tree produced by dae_configParser.
type dae_configListener interface {
	antlr.ParseTreeListener

	// EnterStart is called when entering the start production.
	EnterStart(c *StartContext)

	// EnterBare_literal is called when entering the bare_literal production.
	EnterBare_literal(c *Bare_literalContext)

	// EnterQuote_literal is called when entering the quote_literal production.
	EnterQuote_literal(c *Quote_literalContext)

	// EnterLiteral is called when entering the literal production.
	EnterLiteral(c *LiteralContext)

	// EnterLiteralExpression is called when entering the literalExpression production.
	EnterLiteralExpression(c *LiteralExpressionContext)

	// EnterInput is called when entering the input production.
	EnterInput(c *InputContext)

	// EnterProgramStructureBlcok is called when entering the programStructureBlcok production.
	EnterProgramStructureBlcok(c *ProgramStructureBlcokContext)

	// EnterExpression is called when entering the expression production.
	EnterExpression(c *ExpressionContext)

	// EnterDeclaration is called when entering the declaration production.
	EnterDeclaration(c *DeclarationContext)

	// EnterOptAnnotation is called when entering the optAnnotation production.
	EnterOptAnnotation(c *OptAnnotationContext)

	// EnterFunctionPrototype is called when entering the functionPrototype production.
	EnterFunctionPrototype(c *FunctionPrototypeContext)

	// EnterOptParameterList is called when entering the optParameterList production.
	EnterOptParameterList(c *OptParameterListContext)

	// EnterNonEmptyParameterList is called when entering the nonEmptyParameterList production.
	EnterNonEmptyParameterList(c *NonEmptyParameterListContext)

	// EnterParameter is called when entering the parameter production.
	EnterParameter(c *ParameterContext)

	// EnterRoutingRule is called when entering the routingRule production.
	EnterRoutingRule(c *RoutingRuleContext)

	// EnterOutboundExpr is called when entering the outboundExpr production.
	EnterOutboundExpr(c *OutboundExprContext)

	// EnterFunctionPrototypeExpression is called when entering the functionPrototypeExpression production.
	EnterFunctionPrototypeExpression(c *FunctionPrototypeExpressionContext)

	// EnterRoutingRuleOrDeclarationOrLiteralOrExpressionList is called when entering the routingRuleOrDeclarationOrLiteralOrExpressionList production.
	EnterRoutingRuleOrDeclarationOrLiteralOrExpressionList(c *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext)

	// EnterRoutingRuleList is called when entering the routingRuleList production.
	EnterRoutingRuleList(c *RoutingRuleListContext)

	// ExitStart is called when exiting the start production.
	ExitStart(c *StartContext)

	// ExitBare_literal is called when exiting the bare_literal production.
	ExitBare_literal(c *Bare_literalContext)

	// ExitQuote_literal is called when exiting the quote_literal production.
	ExitQuote_literal(c *Quote_literalContext)

	// ExitLiteral is called when exiting the literal production.
	ExitLiteral(c *LiteralContext)

	// ExitLiteralExpression is called when exiting the literalExpression production.
	ExitLiteralExpression(c *LiteralExpressionContext)

	// ExitInput is called when exiting the input production.
	ExitInput(c *InputContext)

	// ExitProgramStructureBlcok is called when exiting the programStructureBlcok production.
	ExitProgramStructureBlcok(c *ProgramStructureBlcokContext)

	// ExitExpression is called when exiting the expression production.
	ExitExpression(c *ExpressionContext)

	// ExitDeclaration is called when exiting the declaration production.
	ExitDeclaration(c *DeclarationContext)

	// ExitOptAnnotation is called when exiting the optAnnotation production.
	ExitOptAnnotation(c *OptAnnotationContext)

	// ExitFunctionPrototype is called when exiting the functionPrototype production.
	ExitFunctionPrototype(c *FunctionPrototypeContext)

	// ExitOptParameterList is called when exiting the optParameterList production.
	ExitOptParameterList(c *OptParameterListContext)

	// ExitNonEmptyParameterList is called when exiting the nonEmptyParameterList production.
	ExitNonEmptyParameterList(c *NonEmptyParameterListContext)

	// ExitParameter is called when exiting the parameter production.
	ExitParameter(c *ParameterContext)

	// ExitRoutingRule is called when exiting the routingRule production.
	ExitRoutingRule(c *RoutingRuleContext)

	// ExitOutboundExpr is called when exiting the outboundExpr production.
	ExitOutboundExpr(c *OutboundExprContext)

	// ExitFunctionPrototypeExpression is called when exiting the functionPrototypeExpression production.
	ExitFunctionPrototypeExpression(c *FunctionPrototypeExpressionContext)

	// ExitRoutingRuleOrDeclarationOrLiteralOrExpressionList is called when exiting the routingRuleOrDeclarationOrLiteralOrExpressionList production.
	ExitRoutingRuleOrDeclarationOrLiteralOrExpressionList(c *RoutingRuleOrDeclarationOrLiteralOrExpressionListContext)

	// ExitRoutingRuleList is called when exiting the routingRuleList production.
	ExitRoutingRuleList(c *RoutingRuleListContext)
}
