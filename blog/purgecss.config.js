module.exports = {
  content: [
    './public/**/*.html',
    './source/**/*.md',
    './themes/**/layout/**/*.ejs',
    './themes/**/source/**/*.js'
  ],
  css: [
    './public/css/**/*.css',
    './public/fontawesome/**/*.css'
  ],
  // Keep dynamic classes and essential framework classes
  safelist: [
    // FontAwesome icons
    /^fa-/,
    /^fab-/,
    /^fas-/,
    /^far-/,
    /^fal-/,
    /^fad-/,
    /^fass-/,

    // Dynamic state classes
    /active$/,
    /show$/,
    /hide$/,
    /open$/,
    /close$/,
    /expanded$/,
    /collapsed$/,

    // Theme switching
    /dark-mode/,
    /light-mode/,
    /theme-/,

    // Animations
    /animated/,
    /animation-/,
    /transition-/,

    // Layout classes that might be added dynamically
    /sidebar-/,
    /navbar-/,
    /banner-/,
    /article-/,
    /post-/,

    // Typography
    /^h[1-6]$/,
    /^text-/,
    /^font-/,

    // Utility classes
    /^ml?-/,
    /^mr?-/,
    /^mt?-/,
    /^mb?-/,
    /^p[lrtbxy]?-/,
    /^m[lrtbxy]?-/,

    // Code highlighting
    /hljs/,
    /highlight/,
    /language-/,

    // Comment system classes
    /giscus/,
    /gitalk/,
    /waline/,

    // Search functionality
    /search/,
    /autocomplete/,

    // Social links
    /social/,
    /qr/
  ],

  // Remove unused keyframes
  keyframes: true,

  // Remove unused font-face declarations
  fontFace: true,

  // Custom extractors for different file types
  extractors: [
    {
      extractor: content => content.match(/[A-Za-z0-9-_:/]+/g) || [],
      extensions: ['html', 'ejs', 'md']
    },
    {
      extractor: content => content.match(/[A-Za-z0-9-_]+/g) || [],
      extensions: ['js']
    }
  ]
};