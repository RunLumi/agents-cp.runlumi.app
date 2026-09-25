import lumiFulltext from "@/assets/brand/lumi-fulltext.svg";
import lumiMark from "@/assets/brand/lumi-logo.svg";

export function LumiMark({ className }: { className?: string }) {
  return <img src={lumiMark} alt="" className={className} />;
}

export function LumiWordmark({ className }: { className?: string }) {
  return <img src={lumiFulltext} alt="Lumi" className={className} />;
}
