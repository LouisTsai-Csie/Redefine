const { PurgeCSS } = require('purgecss');
const fs = require('fs');
const path = require('path');

// Register the CSS optimization filter
hexo.extend.filter.register('after_generate', async function() {
  const publicDir = this.public_dir;
  const cssDir = path.join(publicDir, 'css');
  const fontawesomeDir = path.join(publicDir, 'fontawesome');

  console.log('🎨 Optimizing CSS files...');

  try {
    // Configure PurgeCSS
    const purgeCSSResults = await new PurgeCSS().purge({
      content: [
        `${publicDir}/**/*.html`,
        `${this.source_dir}/**/*.md`,
        `${this.theme_dir}/layout/**/*.ejs`,
        `${this.theme_dir}/source/**/*.js`
      ],
      css: [
        `${cssDir}/**/*.css`,
        `${fontawesomeDir}/**/*.css`
      ],
      safelist: [
        // FontAwesome icons
        /^fa-/,
        /^fab-/,
        /^fas-/,
        /^far-/,
        /^fal-/,
        /^fad-/,
        /^fass-/,

        // Dynamic classes
        /active$/,
        /show$/,
        /hide$/,
        /open$/,
        /close$/,
        /expanded$/,
        /collapsed$/,

        // Theme classes
        /dark-mode/,
        /light-mode/,
        /theme-/,

        // Animation classes
        /animated/,
        /animation-/,
        /transition-/,

        // Layout
        /sidebar-/,
        /navbar-/,
        /banner-/,
        /article-/,
        /post-/,

        // Code highlighting
        /hljs/,
        /highlight/,
        /language-/,

        // Comment systems
        /giscus/,
        /gitalk/,
        /waline/,

        // Search
        /search/,
        /autocomplete/,

        // Social
        /social/,
        /qr/
      ],
      keyframes: true,
      fontFace: true
    });

    // Write optimized CSS files
    for (const result of purgeCSSResults) {
      const filePath = result.file;
      const optimizedCSS = result.css;

      if (filePath && optimizedCSS) {
        fs.writeFileSync(filePath, optimizedCSS);

        // Calculate size reduction
        const originalSize = fs.statSync(filePath).size;
        const newSize = optimizedCSS.length;
        const reduction = ((originalSize - newSize) / originalSize * 100).toFixed(2);

        console.log(`✅ Optimized ${path.basename(filePath)}: ${reduction}% size reduction`);
      }
    }

    console.log('🎉 CSS optimization completed!');

  } catch (error) {
    console.error('❌ CSS optimization failed:', error.message);
  }
});

// Note: Critical CSS is now handled in theme configuration inject.head
// to avoid contaminating post content and preview text