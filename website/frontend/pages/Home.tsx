import { useState, useEffect } from 'react'
import { HomePage, HomeHeader, HomeHero, HomeFeatures, HomeCTA, HomeFooter, type HomeFeature } from '@usecross/docs'
import { Logo } from '@/components/Logo'

interface HomeProps {
  title: string
  tagline: string
  description: string
  installCommand: string
  ctaText: string
  ctaHref: string
  features: HomeFeature[]
  logoUrl?: string
  heroLogoUrl?: string
  footerLogoUrl?: string
  githubUrl?: string
  navLinks?: Array<{ label: string; href: string }>
}

export default function Home(props: HomeProps) {
  const [showFullLogo, setShowFullLogo] = useState(false)
  const navLinks = props.navLinks ?? [{ label: 'Docs', href: '/docs' }]

  useEffect(() => {
    const handleScroll = () => {
      // Show full logo after scrolling past the hero logo
      setShowFullLogo(window.scrollY > 250)
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <HomePage {...props} navLinks={navLinks}>
      <HomeHeader renderLogo={() => <Logo showFull={showFullLogo} />} />
      <HomeHero />
      <HomeFeatures />
      <HomeCTA />
      <HomeFooter />
    </HomePage>
  )
}
