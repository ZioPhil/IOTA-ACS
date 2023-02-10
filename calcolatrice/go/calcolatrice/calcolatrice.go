// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package calcolatrice

import "github.com/iotaledger/wasp/packages/wasmvm/wasmlib/go/wasmlib"

func funcAdd(ctx wasmlib.ScFuncContext, f *AddContext) {
        var number1 = f.Params.Number1().Value()
	var number2 = f.Params.Number2().Value()
	var res = number1 + number2
	f.State.Res().SetValue(res)
}

func funcDivide(ctx wasmlib.ScFuncContext, f *DivideContext) {
        var number1 = f.Params.Number1().Value()
	var number2 = f.Params.Number2().Value()
	var res = number1 / number2
	f.State.Res().SetValue(res)
}

func funcInit(ctx wasmlib.ScFuncContext, f *InitContext) {
	if f.Params.Owner().Exists() {
		f.State.Owner().SetValue(f.Params.Owner().Value())
		return
	}
	f.State.Owner().SetValue(ctx.RequestSender())
}

func funcMultiply(ctx wasmlib.ScFuncContext, f *MultiplyContext) {
        var number1 = f.Params.Number1().Value()
	var number2 = f.Params.Number2().Value()
	var res = number1 * number2
	f.State.Res().SetValue(res)
}

func funcSetOwner(ctx wasmlib.ScFuncContext, f *SetOwnerContext) {
	f.State.Owner().SetValue(f.Params.Owner().Value())
}

func funcSubtract(ctx wasmlib.ScFuncContext, f *SubtractContext) {
        var number1 = f.Params.Number1().Value()
	var number2 = f.Params.Number2().Value()
	var res = number1 - number2
	f.State.Res().SetValue(res)
}

func viewGetOwner(ctx wasmlib.ScViewContext, f *GetOwnerContext) {
	f.Results.Owner().SetValue(f.State.Owner().Value())
}

func viewGetRes(ctx wasmlib.ScViewContext, f *GetResContext) {
        f.Results.Res().SetValue(f.State.Res().Value())
}
