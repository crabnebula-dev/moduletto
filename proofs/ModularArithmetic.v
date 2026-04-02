(** * Moduletto: Modular Arithmetic Correctness Proofs

    Formal verification that the branchless modular arithmetic operations
    used in Moduletto's constant-time implementation are correct.

    These proofs correspond to the Rust code in src/modn.rs and src/modn_ct.rs.
*)

From Stdlib Require Import ZArith.
From Stdlib Require Import Lia.
From Stdlib Require Import Zdiv.

Open Scope Z_scope.

(** ** Canonical form: values in [0, N) *)

Definition in_range (x N : Z) : Prop := 0 <= x /\ x < N.

(** ** Variable-time modular addition

    The Rust implementation:
<<
    fn add(self, other: Self) -> Self {
        let sum = self.value + other.value;
        if sum >= N { Self { value: sum - N } }
        else        { Self { value: sum } }
    }
>>
*)
Definition vt_mod_add (a b N : Z) : Z :=
  let sum := a + b in
  if Z.leb N sum then sum - N else sum.

Theorem vt_mod_add_correct :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    vt_mod_add a b N = (a + b) mod N.
Proof.
  intros a b N HN [Ha0 HaN] [Hb0 HbN].
  unfold vt_mod_add.
  destruct (Z.leb N (a + b)) eqn:Hcmp.
  - apply Z.leb_le in Hcmp.
    apply (Zmod_unique (a + b) N 1 (a + b - N)); lia.
  - apply Z.leb_gt in Hcmp.
    apply (Zmod_unique (a + b) N 0 (a + b)); lia.
Qed.

(** ** Variable-time modular subtraction *)

Definition vt_mod_sub (a b N : Z) : Z :=
  let diff := a - b in
  if Z.ltb diff 0 then diff + N else diff.

Theorem vt_mod_sub_correct :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    vt_mod_sub a b N = (a - b) mod N.
Proof.
  intros a b N HN [Ha0 HaN] [Hb0 HbN].
  unfold vt_mod_sub.
  destruct (Z.ltb (a - b) 0) eqn:Hcmp.
  - apply Z.ltb_lt in Hcmp.
    apply (Zmod_unique (a - b) N (-1) (a - b + N)); lia.
  - apply Z.ltb_ge in Hcmp.
    apply (Zmod_unique (a - b) N 0 (a - b)); lia.
Qed.

(** ** Variable-time negation *)

Definition vt_mod_neg (a N : Z) : Z :=
  if Z.eqb a 0 then 0 else N - a.

Theorem vt_mod_neg_correct :
  forall a N,
    N > 0 ->
    in_range a N ->
    vt_mod_neg a N = (N - a) mod N.
Proof.
  intros a N HN [Ha0 HaN].
  unfold vt_mod_neg.
  destruct (Z.eqb a 0) eqn:Heq.
  - apply Z.eqb_eq in Heq. subst. rewrite Z.sub_0_r.
    apply (Zmod_unique N N 1 0); lia.
  - apply Z.eqb_neq in Heq.
    apply (Zmod_unique (N - a) N 0 (N - a)); lia.
Qed.

(** ** Branchless (constant-time) modular addition

    The Rust CT implementation:
<<
    let sum = self.value() + other.value();
    let needs_reduction = ct_mask(((N - 1 - sum) >> 63) as i64);
    let reduced = sum - N;
    let result = (reduced & needs_reduction) | (sum & !needs_reduction);
>>

    We model the arithmetic shift as producing either 0 or -1,
    which is the mask behavior on 64-bit two's complement. *)

(** Mask from sign bit: -1 if x < 0, 0 if x >= 0.
    Models (x >> 63) on i64 two's complement. *)
Definition sign_mask (x : Z) : Z :=
  if Z.ltb x 0 then -1 else 0.

Definition ct_mod_add (a b N : Z) : Z :=
  let sum := a + b in
  let needs_reduction := sign_mask (N - 1 - sum) in
  let reduced := sum - N in
  Z.lor (Z.land reduced needs_reduction) (Z.land sum (Z.lnot needs_reduction)).

(** Key lemma: sign_mask produces the correct mask *)
Lemma sign_mask_neg : forall x, x < 0 -> sign_mask x = -1.
Proof.
  intros. unfold sign_mask.
  destruct (Z.ltb x 0) eqn:E; auto.
  apply Z.ltb_ge in E. lia.
Qed.

Lemma sign_mask_nonneg : forall x, x >= 0 -> sign_mask x = 0.
Proof.
  intros. unfold sign_mask.
  destruct (Z.ltb x 0) eqn:E; auto.
  apply Z.ltb_lt in E. lia.
Qed.

(** Bitwise selection lemma: (x & mask) | (y & ~mask) selects x or y *)
Lemma bitmask_select_neg1 : forall x y,
  Z.lor (Z.land x (-1)) (Z.land y (Z.lnot (-1))) = x.
Proof.
  intros.
  replace (Z.lnot (-1)) with 0 by reflexivity.
  rewrite Z.land_0_r. rewrite Z.lor_0_r.
  rewrite Z.land_m1_r. reflexivity.
Qed.

Lemma bitmask_select_0 : forall x y,
  Z.lor (Z.land x 0) (Z.land y (Z.lnot 0)) = y.
Proof.
  intros.
  replace (Z.lnot 0) with (-1) by reflexivity.
  rewrite Z.land_0_r. rewrite Z.lor_0_l.
  rewrite Z.land_m1_r. reflexivity.
Qed.

Theorem ct_mod_add_equiv_vt :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    ct_mod_add a b N = vt_mod_add a b N.
Proof.
  intros a b N HN [Ha0 HaN] [Hb0 HbN].
  unfold ct_mod_add, vt_mod_add.
  destruct (Z.leb N (a + b)) eqn:Hcmp.
  - apply Z.leb_le in Hcmp.
    assert (Hmask: sign_mask (N - 1 - (a + b)) = -1).
    { apply sign_mask_neg. lia. }
    rewrite Hmask. apply bitmask_select_neg1.
  - apply Z.leb_gt in Hcmp.
    assert (Hmask: sign_mask (N - 1 - (a + b)) = 0).
    { apply sign_mask_nonneg. lia. }
    rewrite Hmask. apply bitmask_select_0.
Qed.

(** Combined: CT add is correct mod N *)
Theorem ct_mod_add_correct :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    ct_mod_add a b N = (a + b) mod N.
Proof.
  intros. rewrite ct_mod_add_equiv_vt; auto. apply vt_mod_add_correct; auto.
Qed.

(** ** Branchless (constant-time) modular subtraction *)

Definition ct_mod_sub (a b N : Z) : Z :=
  let diff := a - b in
  let needs_adjustment := sign_mask diff in
  let adjusted := diff + N in
  Z.lor (Z.land adjusted needs_adjustment) (Z.land diff (Z.lnot needs_adjustment)).

Theorem ct_mod_sub_equiv_vt :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    ct_mod_sub a b N = vt_mod_sub a b N.
Proof.
  intros a b N HN [Ha0 HaN] [Hb0 HbN].
  unfold ct_mod_sub, vt_mod_sub.
  destruct (Z.ltb (a - b) 0) eqn:Hcmp.
  - apply Z.ltb_lt in Hcmp.
    assert (Hmask: sign_mask (a - b) = -1).
    { apply sign_mask_neg. lia. }
    rewrite Hmask. apply bitmask_select_neg1.
  - apply Z.ltb_ge in Hcmp.
    assert (Hmask: sign_mask (a - b) = 0).
    { apply sign_mask_nonneg. lia. }
    rewrite Hmask. apply bitmask_select_0.
Qed.

Theorem ct_mod_sub_correct :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    ct_mod_sub a b N = (a - b) mod N.
Proof.
  intros. rewrite ct_mod_sub_equiv_vt; auto. apply vt_mod_sub_correct; auto.
Qed.

(** ** Closure: operations preserve canonical range *)

Theorem vt_mod_add_in_range :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    in_range (vt_mod_add a b N) N.
Proof.
  intros a b N HN [Ha0 HaN] [Hb0 HbN].
  unfold vt_mod_add, in_range.
  destruct (Z.leb N (a + b)) eqn:Hcmp.
  - apply Z.leb_le in Hcmp. lia.
  - apply Z.leb_gt in Hcmp. lia.
Qed.

Theorem vt_mod_sub_in_range :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    in_range (vt_mod_sub a b N) N.
Proof.
  intros a b N HN [Ha0 HaN] [Hb0 HbN].
  unfold vt_mod_sub, in_range.
  destruct (Z.ltb (a - b) 0) eqn:Hcmp.
  - apply Z.ltb_lt in Hcmp. lia.
  - apply Z.ltb_ge in Hcmp. lia.
Qed.

Theorem vt_mod_neg_in_range :
  forall a N,
    N > 0 ->
    in_range a N ->
    in_range (vt_mod_neg a N) N.
Proof.
  intros a N HN [Ha0 HaN].
  unfold vt_mod_neg, in_range.
  destruct (Z.eqb a 0) eqn:Heq.
  - lia.
  - apply Z.eqb_neq in Heq. lia.
Qed.

(** ** Modular multiplication correctness *)

Definition mod_mul (a b N : Z) : Z :=
  (a * b) mod N.

Theorem mod_mul_in_range :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    in_range (mod_mul a b N) N.
Proof.
  intros a b N HN Ha Hb.
  unfold mod_mul, in_range.
  split.
  - apply Z.mod_pos_bound. lia.
  - apply Z.mod_pos_bound. lia.
Qed.

(** ** Algebraic properties *)

Theorem mod_add_comm :
  forall a b N,
    N > 0 ->
    in_range a N ->
    in_range b N ->
    vt_mod_add a b N = vt_mod_add b a N.
Proof.
  intros a b N HN Ha Hb.
  rewrite vt_mod_add_correct; auto.
  rewrite vt_mod_add_correct; auto.
  f_equal. lia.
Qed.

Theorem mod_add_identity :
  forall a N,
    N > 0 ->
    in_range a N ->
    vt_mod_add a 0 N = a.
Proof.
  intros a N HN [Ha0 HaN].
  unfold vt_mod_add.
  replace (a + 0) with a by lia.
  destruct (Z.leb N a) eqn:Hcmp.
  - apply Z.leb_le in Hcmp. lia.
  - reflexivity.
Qed.

Theorem mod_add_inverse :
  forall a N,
    N > 0 ->
    in_range a N ->
    vt_mod_add a (vt_mod_neg a N) N = 0.
Proof.
  intros a N HN [Ha0 HaN].
  unfold vt_mod_neg, vt_mod_add.
  destruct (Z.eqb a 0) eqn:Heq.
  - apply Z.eqb_eq in Heq. subst.
    simpl. destruct (Z.leb N 0) eqn:E; lia.
  - apply Z.eqb_neq in Heq.
    replace (a + (N - a)) with N by lia.
    destruct (Z.leb N N) eqn:E.
    + lia.
    + apply Z.leb_gt in E. lia.
Qed.

Theorem mod_mul_comm :
  forall a b N,
    N > 0 ->
    mod_mul a b N = mod_mul b a N.
Proof.
  intros. unfold mod_mul. f_equal. lia.
Qed.

Theorem mod_mul_identity :
  forall a N,
    N > 1 ->
    in_range a N ->
    mod_mul a 1 N = a.
Proof.
  intros a N HN [Ha0 HaN].
  unfold mod_mul. rewrite Z.mul_1_r.
  apply Z.mod_small. lia.
Qed.

Theorem mod_mul_zero :
  forall a N,
    N > 0 ->
    mod_mul a 0 N = 0.
Proof.
  intros. unfold mod_mul. rewrite Z.mul_0_r.
  apply Z.mod_0_l. lia.
Qed.
