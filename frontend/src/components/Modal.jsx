import { createContext, useCallback, useContext, useState } from 'react'

const ModalContext = createContext(null)

/**
 * Port of dashboard.html's showModal(title, bodyHtml, buttons). Here
 * `body` is a React node (JSX) instead of an HTML string, and each
 * button's `fn` is a real function reference — same shape otherwise:
 * [{ label, cls, fn }].
 */
export function ModalProvider({ children }) {
  const [modal, setModal] = useState(null) // { title, body, buttons } | null

  const showModal = useCallback((title, body, buttons) => {
    setModal({ title, body, buttons })
  }, [])

  const closeModal = useCallback(() => setModal(null), [])

  return (
    <ModalContext.Provider value={{ showModal, closeModal }}>
      {children}
      {modal && (
        <div className="overlay" onClick={(e) => e.target === e.currentTarget && closeModal()}>
          <div className="modal">
            <div className="modal-hd">
              <span className="modal-title">{modal.title}</span>
              <button className="modal-x" onClick={closeModal}>
                <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <line x1="1" y1="1" x2="11" y2="11" />
                  <line x1="11" y1="1" x2="1" y2="11" />
                </svg>
              </button>
            </div>
            <div className="modal-bd">{modal.body}</div>
            <div className="modal-ft">
              {modal.buttons.map((b, i) => (
                <button key={i} className={`btn ${b.cls}`} onClick={b.fn}>{b.label}</button>
              ))}
            </div>
          </div>
        </div>
      )}
    </ModalContext.Provider>
  )
}

export function useModal() {
  const ctx = useContext(ModalContext)
  if (!ctx) throw new Error('useModal must be used within ModalProvider')
  return ctx
}
