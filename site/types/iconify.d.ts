import 'react'

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'iconify-icon': React.DetailedHTMLProps<
        React.HTMLAttributes<HTMLElement> & {
          icon: string
          width?: string | number
          height?: string | number
          inline?: boolean
          mode?: 'svg' | 'style' | 'bg' | 'mask'
          flip?: 'horizontal' | 'vertical' | 'horizontal,vertical'
          rotate?: '90deg' | '180deg' | '270deg' | number
          class?: string
        },
        HTMLElement
      >
    }
  }
}
