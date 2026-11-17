// Ambient "breathing" aura plus a slowly drifting dot-matrix grid. Purely decorative.
export default function Background() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute -left-40 -top-40 h-[42rem] w-[42rem] animate-breathe rounded-full bg-[radial-gradient(circle,rgba(56,189,248,0.16),transparent_65%)] blur-2xl" />
      <div
        className="absolute -bottom-56 -right-40 h-[46rem] w-[46rem] animate-breathe rounded-full bg-[radial-gradient(circle,rgba(52,211,153,0.10),transparent_65%)] blur-2xl"
        style={{ animationDelay: "-6s" }}
      />
      <div className="absolute left-1/2 top-1/3 h-[30rem] w-[30rem] -translate-x-1/2 animate-breathe rounded-full bg-[radial-gradient(circle,rgba(167,139,250,0.06),transparent_65%)] blur-2xl" style={{ animationDelay: "-3s" }} />
      <div
        className="absolute inset-0 animate-drift opacity-[0.22]"
        style={{
          backgroundImage: "radial-gradient(rgba(148,163,184,0.35) 1px, transparent 1px)",
          backgroundSize: "28px 28px",
          maskImage: "radial-gradient(ellipse at center, black 30%, transparent 80%)",
          WebkitMaskImage: "radial-gradient(ellipse at center, black 30%, transparent 80%)",
        }}
      />
    </div>
  );
}
