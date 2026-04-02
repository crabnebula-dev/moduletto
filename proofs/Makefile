# Moduletto Formal Verification
#
# Targets:
#   make         - Compile all Coq proofs and OCaml tests
#   make coq     - Compile only Coq proofs
#   make ocaml   - Compile and run OCaml test harness
#   make clean   - Remove build artifacts

COQC = coqc
COQFLAGS = -Q . Moduletto

OCAMLOPT = ocamlfind ocamlopt
OCAMLC = ocaml

COQ_SOURCES = ModularArithmetic.v BarrettReduction.v ConstantTime.v NTT.v
COQ_VOS = $(COQ_SOURCES:.v=.vo)

.PHONY: all coq ocaml clean

all: coq ocaml

# ── Coq proofs ──────────────────────────────────────────────────────

coq: $(COQ_VOS)

%.vo: %.v
	$(COQC) $(COQFLAGS) $<

# Dependencies (none between files — all are independent)

# ── OCaml test harness ──────────────────────────────────────────────

ocaml: test_moduletto.ml
	@echo "=== Compiling and running OCaml tests ==="
	$(OCAMLC) test_moduletto.ml

# ── Clean ───────────────────────────────────────────────────────────

clean:
	rm -f *.vo *.vok *.vos *.glob .*.aux *.cmi *.cmx *.o test_moduletto
