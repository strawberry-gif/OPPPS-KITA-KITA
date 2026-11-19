const ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.4"/><rect x="14" y="3" width="7" height="7" rx="1.4"/><rect x="3" y="14" width="7" height="7" rx="1.4"/><rect x="14" y="14" width="7" height="7" rx="1.4"/>',
  activity: '<path d="M3 12h4l2.5-7 5 14L17 12h4"/>',
  network: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8.2 7.3 10.8 16M15.8 7.3 13.2 16M8.5 6h7"/>',
  share: '<circle cx="18" cy="5" r="2.6"/><circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="19" r="2.6"/><path d="m8.4 10.8 7.2-4.3M8.4 13.2l7.2 4.3"/>',
  "shield-alert": '<path d="M12 3 20 6v6c0 4.8-3.4 8.5-8 10-4.6-1.5-8-5.2-8-10V6l8-3Z"/><path d="M12 8v5"/><circle cx="12" cy="16.4" r=".9" fill="currentColor" stroke="none"/>',
  shield: '<path d="M12 3 20 6v6c0 4.8-3.4 8.5-8 10-4.6-1.5-8-5.2-8-10V6l8-3Z"/>',
  "shield-check": '<path d="M12 3 20 6v6c0 4.8-3.4 8.5-8 10-4.6-1.5-8-5.2-8-10V6l8-3Z"/><path d="m8.8 12 2.2 2.2 4.4-4.6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.4 4 5.6 4 9s-1.4 6.6-4 9c-2.6-2.4-4-5.6-4-9s1.4-6.6 4-9Z"/>',
  "alert-triangle": '<path d="M10.3 3.8 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.8a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4"/><circle cx="12" cy="17" r=".9" fill="currentColor" stroke="none"/>',
  "alert-circle": '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V13"/><circle cx="12" cy="16.6" r=".9" fill="currentColor" stroke="none"/>',
  "bar-chart": '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  cpu: '<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  sliders: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h8M16 18h4"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="14" cy="18" r="2"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 8.2A7 7 0 0 1 18.8 7M17.9 15.8A7 7 0 0 1 5.2 17"/>',
  download: '<path d="M12 3v12M7.5 10.5 12 15l4.5-4.5"/><path d="M4 18v2.5h16V18"/>',
  upload: '<path d="M12 16V4M7.5 8.5 12 4l4.5 4.5"/><path d="M4 18v2.5h16V18"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  check: '<path d="m4.5 12.5 5 5 10-11"/>',
  "check-circle": '<circle cx="12" cy="12" r="9"/><path d="m8 12.2 2.6 2.6 5.6-5.8"/>',
  "chevron-left": '<path d="m14.5 6-6 6 6 6"/>',
  "chevron-right": '<path d="m9.5 6 6 6-6 6"/>',
  "chevrons-left": '<path d="m11 6-6 6 6 6M18 6l-6 6 6 6"/>',
  "chevrons-right": '<path d="m13 6 6 6-6 6M6 6l6 6-6 6"/>',
  play: '<path d="M7 4.8v14.4L19.5 12 7 4.8Z"/>',
  square: '<rect x="6" y="6" width="12" height="12" rx="1.6"/>',
  "log-out": '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 8l-4 4 4 4M6 12h9"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9Z"/><path d="M10 21h4"/>',
  database: '<ellipse cx="12" cy="5.5" rx="7.5" ry="3"/><path d="M4.5 5.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6"/><path d="M4.5 11.5v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5V12l3.2 2"/>',
  server: '<rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
  wifi: '<path d="M2.5 8.5a15 15 0 0 1 19 0M5.5 12a10.5 10.5 0 0 1 13 0M8.5 15.4a6 6 0 0 1 7 0"/><circle cx="12" cy="19" r="1" fill="currentColor" stroke="none"/>',
  filter: '<path d="M3 5h18l-7 8v5.5l-4 2V13L3 5Z"/>',
  "file-text": '<path d="M6 2.5h8L19 7v14.5H6V2.5Z"/><path d="M14 2.5V7h5M9 11h6M9 15h6M9 18h4"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  lock: '<rect x="4.5" y="10" width="15" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1" fill="currentColor" stroke="none"/>',
  eye: '<path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12Z"/><circle cx="12" cy="12" r="2.8"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><circle cx="12" cy="7.8" r=".9" fill="currentColor" stroke="none"/>',
  zap: '<path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5M3 17.5l9 5 9-5"/>',
  "arrow-up-right": '<path d="M7 17 17 7M8 7h9v9"/>',
  "external-link": '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  trash: '<path d="M4 7h16M9 7V4.5h6V7M6.5 7l1 14h9l1-14M10 11v6M14 11v6"/>',
  edit: '<path d="M4 20h4L20 8l-4-4L4 16v4Z"/><path d="m13.5 6.5 4 4"/>',
  "map-pin": '<path d="M12 21s7-6.2 7-11a7 7 0 1 0-14 0c0 4.8 7 11 7 11Z"/><circle cx="12" cy="10" r="2.6"/>',
  inbox: '<path d="M3 12h5l2 3h4l2-3h5"/><path d="M5 4h14l2 8v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-6l2-8Z"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  calendar: '<rect x="3.5" y="5" width="17" height="15" rx="2"/><path d="M8 3v4M16 3v4M3.5 10h17"/>',
  flag: '<path d="M5 21V3h13l-2.5 4.5L18 12H5"/>',
  "rotate-ccw": '<path d="M4 5v5h5"/><path d="M4.8 10A8 8 0 1 1 6 16.5"/>',
  "eye-off": '<path d="M3 3l18 18"/><path d="M10.6 6.1A9.7 9.7 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-2.2 2.8M6.6 6.7C3.8 8.5 2 12 2 12s3.5 6 10 6a10 10 0 0 0 3.3-.55"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 7 8.5 6 8.5-6"/>',
  "user-plus": '<circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 12-5"/><path d="M18 14v6M15 17h6"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8M16 4l3 3M14 6l2 2"/>',
  "trending-up": '<path d="m3 17 6-6 4 4 7-7"/><path d="M15 8h5v5"/>',
  "trending-down": '<path d="m3 7 6 6 4-4 7 7"/><path d="M15 16h5v-5"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
  hash: '<path d="M9 3 7 21M17 3l-2 18M4 8h17M3 16h17"/>',
  radio: '<circle cx="12" cy="12" r="2.5"/><path d="M7.5 7.5a6.5 6.5 0 0 0 0 9M16.5 7.5a6.5 6.5 0 0 1 0 9"/><path d="M4.6 4.6a10.5 10.5 0 0 0 0 14.8M19.4 4.6a10.5 10.5 0 0 1 0 14.8"/>',
};

export function icon(name, className = "") {
  const body = ICONS[name] || ICONS.info;
  return `<svg class="${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

export const BRAND_MARK = `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 2.5 20 5.7v5.5c0 4.8-3.4 8.5-8 10.3-4.6-1.8-8-5.5-8-10.3V5.7L12 2.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
  <path d="M12 7v4.2m0 0 3 2.2m-3-2.2-3 2.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
  <circle cx="12" cy="6.4" r="1.3" fill="currentColor"/>
  <circle cx="15.6" cy="14.2" r="1.3" fill="currentColor"/>
  <circle cx="8.4" cy="14.2" r="1.3" fill="currentColor"/>
</svg>`;
