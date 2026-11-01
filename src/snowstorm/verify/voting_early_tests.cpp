// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see COPYING.
#include "../src/voting_preview.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
using snowstorm::Error;
using snowstorm::detail::preview_voting;
namespace {
std::uint64_t checks{};
void require(bool value,const char *message){++checks;if(!value)throw std::runtime_error(message);}
std::uint64_t choose(std::uint64_t n,std::uint64_t k){
    if(k>n)return 0;k=std::min(k,n-k);std::uint64_t value=1;
    for(std::uint64_t i=1;i<=k;++i)value=value*(n-k+i)/i;
    return value;
}
std::uint64_t mass(std::uint64_t n,std::uint64_t m,std::uint64_t k,std::uint64_t y){
    return y<=m&&y<=k&&k-y<=n-m?choose(m,y)*choose(n-m,k-y):0;
}
double ratio(std::uint64_t n,std::uint64_t m0,std::uint64_t m1,std::uint64_t k,std::uint64_t y){
    if(k==0)return 0;const auto a=mass(n,m0,k,y),b=mass(n,m1,k,y);
    if(a&&b)return std::log2(static_cast<double>(b)/static_cast<double>(a));
    const auto infinity=std::numeric_limits<double>::infinity();
    if(b)return infinity;if(a)return -infinity;
    return y>std::min(k,m0)?infinity:-infinity;
}
double clamp(double current,double increment,double bound){
    if(std::isinf(increment))return increment>0?bound:0;
    return std::clamp(current+increment,0.,bound);
}
bool same(double a,double b){return std::isinf(b)?std::isinf(a)&&std::signbit(a)==std::signbit(b):std::abs(a-b)<1e-9;}
void exhaustive(){
    std::uint64_t tuples=0,completions=0;
    for(std::uint64_t n=1;n<=12;++n)for(std::uint64_t m0=0;m0<n;++m0)for(std::uint64_t m1=m0+1;m1<=n;++m1)
    for(std::uint64_t k=0;k<=n;++k)for(std::uint64_t answered=0;answered<=k;++answered)for(std::uint64_t y=0;y<=answered;++y){
        const auto expected=ratio(n,m0,m1,k,y);++tuples;
        for(double current:{0.,1.5,4.})for(bool ready:{false,true}){
            const auto preview=preview_voting(n,m0,m1,k,answered,y,current,4,ready);
            require(preview.error==Error::ok,"valid tuple rejected");require(same(preview.lower_llr,expected),"independent full-K ratio mismatch");
            require(same(preview.confidence,clamp(current,expected,4)),"saturated lower confidence mismatch");
            require(!preview.eligible||(k!=0&&ready&&preview.confidence==4),"eligibility prerequisites missing");
            for(auto final_y=y;final_y<=y+k-answered;++final_y){
                const auto future=ratio(n,m0,m1,k,final_y);++completions;
                require(preview.lower_llr<=future+1e-9,"possible completion violates lower LLR");
                require(preview.confidence<=clamp(current,future,4)+1e-9,"possible completion lowers confidence");
                require(!preview.eligible||clamp(current,future,4)>=4-1e-9,"early eligibility not conservative");
            }
        }
    }
    std::cout<<"T13 pure preview exhaustive D1..12: "<<tuples<<" partial tuples, "<<completions<<" possible-completion comparisons\n";
}
void boundaries(){
    const auto infinity=std::numeric_limits<double>::infinity();const auto nan=std::numeric_limits<double>::quiet_NaN();
    require(preview_voting(32,19,26,8,9,0,0,35,true).error!=Error::ok,"answered>K accepted");
    require(preview_voting(32,19,26,8,2,3,0,35,true).error!=Error::ok,"matches>answered accepted");
    require(preview_voting(32,19,26,33,0,0,0,35,true).error!=Error::ok,"K>D accepted");
    require(preview_voting(32,26,19,8,0,0,0,35,true).error!=Error::ok,"reversed hypotheses accepted");
    require(preview_voting(32,19,19,8,0,0,0,35,true).error!=Error::ok,"equal hypotheses accepted");
    require(preview_voting(32,19,33,8,0,0,0,35,true).error!=Error::ok,"M1>D accepted");
    require(preview_voting(32,19,26,8,0,0,0,0,true).error!=Error::ok,"zero threshold accepted");
    for(double current:{-1.,36.,infinity,-infinity,nan})require(preview_voting(32,19,26,8,0,0,current,35,true).error!=Error::ok,"invalid C accepted");
    for(bool ready:{false,true})for(double current:{0.,35.}){
        auto p=preview_voting(32,19,26,0,0,0,current,35,ready);require(p.error==Error::ok&&p.lower_llr==0&&p.confidence==current&&!p.eligible,"zero-K wave ended");
        p=preview_voting(0,0,0,0,0,0,current,35,ready);require(p.error==Error::ok&&p.lower_llr==0&&p.confidence==current&&!p.eligible,"empty population ended");
    }
    const auto high=preview_voting(5,2,4,5,4,4,0,35,true);require(high.error==Error::ok&&high.lower_llr==infinity&&high.confidence==35&&high.eligible,"positive infinity branch");
    const auto low=preview_voting(5,2,4,5,1,1,35,35,true);require(low.error==Error::ok&&low.lower_llr==-infinity&&low.confidence==0&&!low.eligible,"negative infinity branch");
    require(!preview_voting(5,2,4,5,4,4,0,35,false).eligible,"transaction readiness ignored");
    const auto full=ratio(32,19,26,8,6),partial=ratio(32,19,26,6,6);
    require(std::isfinite(full)&&full<partial,"bad full-K regression fixture");
    const double current=35-(full+partial)/2;
    auto preview=preview_voting(32,19,26,8,6,6,current,35,true);
    require(!preview.eligible&&same(preview.lower_llr,full),"unanswered peers silently removed from K");
    require(clamp(current,partial,35)==35,"wrong answered-only calculation did not separate");
    // Six matching responses can be sufficient despite two unanswered peers;
    // this proves only mathematical eligibility, not network/timer behavior.
    const auto sufficient=preview_voting(32,19,26,8,6,6,35,35,true);
    require(sufficient.eligible,"conservative majority fixture should qualify");
    for(unsigned repeat=0;repeat<10000;++repeat){const auto next=preview_voting(32,19,26,8,6,6,current,35,true);
        require(next.lower_llr==preview.lower_llr&&next.confidence==preview.confidence&&next.eligible==preview.eligible,"pure repeats accumulated state");}
}
void finite_null(){
    // Exact integer-count DP: D5,M0=3,M1=4,K4. Under the null, Y3 has
    // mass2/5 and increment+1; Y2 has mass3/5 and increment-infinity.
    // Absorbing false crossing in25 waves at B12 (epsilon .01) is bounded.
    // This is a finite calibration example, not an unlimited-height theorem.
    constexpr unsigned bound=12,waves=25;std::array<std::uint64_t,bound> counts{};counts[0]=1;
    std::uint64_t hits=0,total=1;
    for(unsigned wave=0;wave<waves;++wave){std::array<std::uint64_t,bound> next{};auto new_hits=hits*5;
        for(unsigned current=0;current<bound;++current)for(std::uint64_t y:{2,3}){
            const auto weight=mass(5,3,4,y);const auto p=preview_voting(5,3,4,4,4,y,current,bound,true);
            require(p.error==Error::ok,"null DP preview error");
            if(p.eligible)new_hits+=counts[current]*weight;
            else next[static_cast<unsigned>(std::lround(p.confidence))]+=counts[current]*weight;
        }
        counts=next;hits=new_hits;total*=5;
    }
    require(hits<=total/100,"finite25-wave null bound exceeded");
    std::uint64_t mass_sum=hits;for(auto count:counts)mass_sum+=count;require(mass_sum==total,"null probability mass lost");
    std::cout<<"T13 finite null: "<<hits<<"/"<<total<<" crossings in25waves (epsilon .01)\n";
}
}
int main(){try{exhaustive();boundaries();finite_null();std::cout<<"PASS T13 pure early preview: "<<checks<<" checks\n";}catch(const std::exception &e){std::cerr<<"FAIL: "<<e.what()<<" after "<<checks<<" checks\n";return 1;}}
