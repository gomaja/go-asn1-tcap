package tcap

import wire "github.com/gomaja/go-asn1/telecom/ss7/tcap"

// ITU-T Q.773 (06/97) clause 3.1 and Annex A bind the same component syntax
// at each message site. These copies go once the messages share
// ComponentPortion's types: https://github.com/gomaja/go-asn1/issues/153.
func componentsForBegin(v *wire.ComponentPortion) *wire.TCMessageBeginComponentsBound {
	if v == nil {
		return nil
	}
	out := &wire.TCMessageBeginComponentsBound{Values: make([]wire.TCMessageBeginComponentsElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.TCMessageBeginComponentsElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.TCMessageBeginComponentsElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.TCMessageBeginComponentsElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsFromBegin(v *wire.TCMessageBeginComponentsBound) *wire.ComponentPortion {
	if v == nil {
		return nil
	}
	out := &wire.ComponentPortion{Values: make([]wire.ComponentPortionElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.ComponentPortionElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.ComponentPortionElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.ComponentPortionElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.ComponentPortionElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsForContinue(v *wire.ComponentPortion) *wire.TCMessageContinueComponentsBound {
	if v == nil {
		return nil
	}
	out := &wire.TCMessageContinueComponentsBound{Values: make([]wire.TCMessageContinueComponentsElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.TCMessageContinueComponentsElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.TCMessageContinueComponentsElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.TCMessageContinueComponentsElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsFromContinue(v *wire.TCMessageContinueComponentsBound) *wire.ComponentPortion {
	if v == nil {
		return nil
	}
	out := &wire.ComponentPortion{Values: make([]wire.ComponentPortionElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.ComponentPortionElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.ComponentPortionElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.ComponentPortionElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.ComponentPortionElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsForEnd(v *wire.ComponentPortion) *wire.TCMessageEndComponentsBound {
	if v == nil {
		return nil
	}
	out := &wire.TCMessageEndComponentsBound{Values: make([]wire.TCMessageEndComponentsElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.TCMessageEndComponentsElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.TCMessageEndComponentsElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.TCMessageEndComponentsElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsFromEnd(v *wire.TCMessageEndComponentsBound) *wire.ComponentPortion {
	if v == nil {
		return nil
	}
	out := &wire.ComponentPortion{Values: make([]wire.ComponentPortionElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.ComponentPortionElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.ComponentPortionElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.ComponentPortionElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.ComponentPortionElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsForUnidirectional(v *wire.ComponentPortion) *wire.TCMessageUnidirectionalComponentsBound {
	if v == nil {
		return nil
	}
	out := &wire.TCMessageUnidirectionalComponentsBound{Values: make([]wire.TCMessageUnidirectionalComponentsElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.TCMessageUnidirectionalComponentsElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.TCMessageUnidirectionalComponentsElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.TCMessageUnidirectionalComponentsElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentsFromUnidirectional(v *wire.TCMessageUnidirectionalComponentsBound) *wire.ComponentPortion {
	if v == nil {
		return nil
	}
	out := &wire.ComponentPortion{Values: make([]wire.ComponentPortionElemBound, len(v.Values))}
	for i, c := range v.Values {
		d := wire.ComponentPortionElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
		if r := c.BasicROS; r != nil {
			d.BasicROS = &wire.ComponentPortionElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
			if a := r.Invoke; a != nil {
				d.BasicROS.Invoke = &wire.ComponentPortionElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
				if a.LinkedId != nil {
					d.BasicROS.Invoke.LinkedId = &wire.ComponentPortionElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
				}
			}
		}
		out.Values[i] = d
	}
	return out
}

func componentValue(c wire.Component) wire.ComponentPortionElemBound {
	d := wire.ComponentPortionElemBound{Choice: c.Choice, ReturnResultNotLast: c.ReturnResultNotLast}
	if r := c.BasicROS; r != nil {
		d.BasicROS = &wire.ComponentPortionElemBasicROSBound{Choice: r.Choice, ReturnResult: r.ReturnResult, ReturnError: r.ReturnError, Reject: r.Reject}
		if a := r.Invoke; a != nil {
			d.BasicROS.Invoke = &wire.ComponentPortionElemBasicROSInvokeBound{InvokeId: a.InvokeId, Opcode: a.Opcode, Argument: a.Argument}
			if a.LinkedId != nil {
				d.BasicROS.Invoke.LinkedId = &wire.ComponentPortionElemBasicROSInvokeBoundLinkedId{Choice: a.LinkedId.Choice, Present: a.LinkedId.Present, Absent: a.LinkedId.Absent}
			}
		}
	}
	return d
}
