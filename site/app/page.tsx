import { AuthHero } from "@/components/auth-hero";
import { AuthHero2 } from "@/components/auth-hero-2";
import { AuthHero3 } from "@/components/auth-hero-3";

import { Navbar } from "@/components/navbar";

export default function Home() {
  return (
    <>
      <Navbar />
      <AuthHero />
    </>
  );
}
