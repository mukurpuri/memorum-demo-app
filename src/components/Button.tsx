import React from "react";

// Icon components for session management UI
const Icons = {
  logout: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
    </svg>
  ),
  revoke: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  ),
  device: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
    </svg>
  ),
  warning: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
  check: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  ),
};

export type IconName = keyof typeof Icons;

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost" | "warning" | "success";
  size?: "sm" | "md" | "lg" | "icon";
  loading?: boolean;
  icon?: IconName;
  iconPosition?: "left" | "right";
  children?: React.ReactNode;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  icon,
  iconPosition = "left",
  children,
  className = "",
  disabled,
  ...props
}: ButtonProps) {
  const baseStyles = "inline-flex items-center justify-center font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2";
  
  const variantStyles = {
    primary: "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500",
    secondary: "bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-500",
    danger: "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500",
    ghost: "bg-transparent text-gray-700 hover:bg-gray-100 focus:ring-gray-500",
    warning: "bg-amber-500 text-white hover:bg-amber-600 focus:ring-amber-400",
    success: "bg-emerald-600 text-white hover:bg-emerald-700 focus:ring-emerald-500",
  };
  
  const sizeStyles = {
    sm: "px-3 py-1.5 text-sm",
    md: "px-4 py-2 text-base",
    lg: "px-6 py-3 text-lg",
    icon: "p-2", // Square icon-only button
  };
  
  const disabledStyles = disabled || loading
    ? "opacity-50 cursor-not-allowed"
    : "";

  const iconElement = icon ? Icons[icon] : null;
  
  return (
    <button
      className={`${baseStyles} ${variantStyles[variant]} ${sizeStyles[size]} ${disabledStyles} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg
          className="animate-spin -ml-1 mr-2 h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
          />
        </svg>
      )}
      {!loading && iconElement && iconPosition === "left" && (
        <span className={children ? "mr-2" : ""}>{iconElement}</span>
      )}
      {children}
      {!loading && iconElement && iconPosition === "right" && (
        <span className={children ? "ml-2" : ""}>{iconElement}</span>
      )}
    </button>
  );
}

// ============================================================================
// Session Management Button Presets
// ============================================================================

interface SessionButtonProps extends Omit<ButtonProps, "variant" | "icon"> {
  sessionId?: string;
}

/**
 * Revoke Session Button
 * Used in Active Sessions UI to revoke a specific session
 */
export function RevokeSessionButton({ children = "Revoke", ...props }: SessionButtonProps) {
  return (
    <Button variant="danger" icon="revoke" size="sm" {...props}>
      {children}
    </Button>
  );
}

/**
 * Logout All Button
 * Used to log out from all devices
 */
export function LogoutAllButton({ children = "Logout All Devices", ...props }: SessionButtonProps) {
  return (
    <Button variant="warning" icon="logout" {...props}>
      {children}
    </Button>
  );
}

/**
 * Suspicious Session Indicator
 * Shows warning state for potentially compromised sessions
 */
export function SuspiciousSessionBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-amber-800 bg-amber-100 rounded-full">
      {Icons.warning}
      Suspicious Activity
    </span>
  );
}

/**
 * Current Session Badge
 * Indicates which session is the current one
 */
export function CurrentSessionBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium text-emerald-800 bg-emerald-100 rounded-full">
      {Icons.check}
      Current Session
    </span>
  );
}
