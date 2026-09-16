// Shared provider picker.
//
// An "Add identity" trigger button that opens a dropdown menu of OpenID
// Providers. Used by BOTH the popup and the login consent page so choosing an
// OP is the same experience everywhere: click Add -> pick a provider. The user
// always chooses the OP explicitly; we never guess a default.

import { providerList } from './config.js'

// mountProviderPicker wires a trigger button to a dropdown menu element.
//   trigger:  the button that opens/closes the menu
//   menu:     the (initially hidden) container that will hold the options
//   onChoose: (providerId) => void, called when a provider is picked
export function mountProviderPicker(trigger, menu, onChoose) {
  menu.innerHTML = ''
  menu.hidden = true
  menu.classList.add('op-menu')
  trigger.setAttribute('aria-haspopup', 'true')
  trigger.setAttribute('aria-expanded', 'false')

  for (const p of providerList) {
    const item = document.createElement('button')
    item.type = 'button'
    item.className = 'op-option'

    const badge = document.createElement('span')
    badge.className = `op-badge op-badge-${p.id}`
    badge.setAttribute('aria-hidden', 'true')
    badge.textContent = p.label.charAt(0)

    const label = document.createElement('span')
    label.textContent = `Continue with ${p.label}`

    item.append(badge, label)
    item.addEventListener('click', () => {
      close()
      onChoose(p.id)
    })
    menu.append(item)
  }

  function open() {
    menu.hidden = false
    trigger.setAttribute('aria-expanded', 'true')
  }
  function close() {
    menu.hidden = true
    trigger.setAttribute('aria-expanded', 'false')
  }
  function toggle() {
    if (menu.hidden) open()
    else close()
  }

  trigger.addEventListener('click', (e) => {
    e.stopPropagation()
    toggle()
  })
  // Close on outside click or Escape.
  document.addEventListener('click', (e) => {
    if (!menu.hidden && !menu.contains(e.target) && e.target !== trigger) close()
  })
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close()
  })

  return { open, close, toggle }
}
