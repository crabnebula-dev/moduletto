use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use moduletto::modn_ct::ConstantTimeOps;
use moduletto::ntt::{NTTPoly, KYBER_Q};
use moduletto::ModN;

type KyberMod = ModN<KYBER_Q>;

// ── Scalar ModN operations ───────────────────────────────────────────────────

fn bench_modn_scalar(c: &mut Criterion) {
    let mut g = c.benchmark_group("modn_scalar");

    let a = KyberMod::new(1234);
    let b = KyberMod::new(5678);

    g.bench_function("add", |bench| {
        bench.iter(|| black_box(a) + black_box(b))
    });
    g.bench_function("sub", |bench| {
        bench.iter(|| black_box(a) - black_box(b))
    });
    g.bench_function("mul", |bench| {
        bench.iter(|| black_box(a) * black_box(b))
    });
    g.bench_function("neg", |bench| bench.iter(|| -black_box(a)));
    g.bench_function("pow_small", |bench| {
        bench.iter(|| black_box(a).pow(black_box(100)))
    });
    g.bench_function("pow_large", |bench| {
        bench.iter(|| black_box(a).pow(black_box(u64::MAX / 2)))
    });
    g.bench_function("inverse", |bench| {
        bench.iter(|| black_box(a).inverse())
    });

    g.finish();
}

// ── Constant-time ModN operations ────────────────────────────────────────────

fn bench_modn_ct(c: &mut Criterion) {
    let mut g = c.benchmark_group("modn_ct");

    let a = KyberMod::new(1234);
    let b = KyberMod::new(5678);

    g.bench_function("ct_add", |bench| {
        bench.iter(|| black_box(a).ct_add(black_box(b)))
    });
    g.bench_function("ct_sub", |bench| {
        bench.iter(|| black_box(a).ct_sub(black_box(b)))
    });
    g.bench_function("ct_mul", |bench| {
        bench.iter(|| black_box(a).ct_mul(black_box(b)))
    });
    g.bench_function("ct_neg", |bench| {
        bench.iter(|| black_box(a).ct_neg())
    });
    g.bench_function("ct_eq", |bench| {
        bench.iter(|| black_box(a).ct_eq(black_box(b)))
    });
    g.bench_function("ct_lt", |bench| {
        bench.iter(|| black_box(a).ct_lt(black_box(b)))
    });
    g.bench_function("ct_select", |bench| {
        bench.iter(|| KyberMod::ct_select(black_box(a), black_box(b), black_box(1u8)))
    });

    g.finish();
}

// ── NTT polynomial operations ────────────────────────────────────────────────

fn make_poly(seed: i64) -> NTTPoly {
    let coeffs: Vec<i64> = (0..256).map(|i| (seed * 31 + i as i64 * 7) % KYBER_Q).collect();
    NTTPoly::from_slice(&coeffs)
}

fn bench_ntt(c: &mut Criterion) {
    let mut g = c.benchmark_group("ntt");

    let p = make_poly(42);
    let q = make_poly(137);

    g.bench_function("forward_ntt", |bench| {
        bench.iter(|| black_box(&p).ntt())
    });
    g.bench_function("inverse_ntt", |bench| {
        let p_ntt = p.ntt();
        bench.iter(|| black_box(&p_ntt).intt())
    });
    g.bench_function("mul_ntt", |bench| {
        bench.iter(|| black_box(&p).mul_ntt(black_box(&q)))
    });
    g.bench_function("mul_schoolbook", |bench| {
        bench.iter(|| black_box(&p).mul_schoolbook(black_box(&q)))
    });
    g.bench_function("poly_add", |bench| {
        bench.iter(|| black_box(&p).add(black_box(&q)))
    });
    g.bench_function("poly_sub", |bench| {
        bench.iter(|| black_box(&p).sub(black_box(&q)))
    });

    g.finish();
}

// ── Constant-time NTT operations ─────────────────────────────────────────────

fn bench_ct_ntt(c: &mut Criterion) {
    let mut g = c.benchmark_group("ntt_ct");

    let p = make_poly(42);
    let q = make_poly(137);

    g.bench_function("ct_forward_ntt", |bench| {
        bench.iter(|| black_box(&p).ct_ntt())
    });
    g.bench_function("ct_inverse_ntt", |bench| {
        let p_ntt = p.ct_ntt();
        bench.iter(|| black_box(&p_ntt).ct_intt())
    });
    g.bench_function("ct_mul_ntt", |bench| {
        bench.iter(|| black_box(&p).ct_mul_ntt(black_box(&q)))
    });
    g.bench_function("ct_poly_add", |bench| {
        bench.iter(|| black_box(&p).ct_add(black_box(&q)))
    });
    g.bench_function("ct_poly_sub", |bench| {
        bench.iter(|| black_box(&p).ct_sub(black_box(&q)))
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_modn_scalar,
    bench_modn_ct,
    bench_ntt,
    bench_ct_ntt
);
criterion_main!(benches);
