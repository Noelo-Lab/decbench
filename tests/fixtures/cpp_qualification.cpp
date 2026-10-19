#ifdef _WIN32
static_assert(sizeof(long) == 4);
#else
static_assert(sizeof(long) == 8);
#endif
static_assert(sizeof(void*) == 8);
struct Guard { Guard(); ~Guard(); };
template<int N> __attribute__((noinline)) int select_value(int x) {
    if constexpr (N > 0) return x + N;
    else return x - N;
}
extern "C" int qualification_probe(int x) {
    Guard guard;
    if (x < 0) throw x;
    return select_value<2>(x) + select_value<-2>(x);
}
