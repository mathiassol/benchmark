


(function() {
  
    async function generateFingerprint() {
      
        const components = [
            navigator.userAgent,
            navigator.language,
            screen.colorDepth,
            screen.width + 'x' + screen.height,
            new Date().getTimezoneOffset(),
            navigator.platform,
            navigator.hardwareConcurrency || 'unknown',
            navigator.deviceMemory || 'unknown',
            !!navigator.doNotTrack || !!navigator.globalPrivacyControl
        ];

      
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
          
            canvas.width = 200;
            canvas.height = 50;
            ctx.textBaseline = "top";
            ctx.font = "14px Arial";
            ctx.fillStyle = "#f60";
            ctx.fillRect(10, 10, 50, 30);
            ctx.fillStyle = "#069";
            ctx.fillText("WASD Typing Test", 2, 15);
          
            components.push(canvas.toDataURL());
        } catch (e) {
          
        }

      
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            if (gl) {
                components.push(
                    gl.getParameter(gl.VENDOR),
                    gl.getParameter(gl.RENDERER)
                );
            }
        } catch (e) {
          
        }

      
        const fingerprint = components.join('###');

      
        if (window.crypto && window.crypto.subtle) {
            const msgBuffer = new TextEncoder().encode(fingerprint);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
          
            let hash = 0;
            for (let i = 0; i < fingerprint.length; i++) {
                const char = fingerprint.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return 'fallback-' + Math.abs(hash).toString(16);
        }
    }

  
    async function getMachineId() {
        const STORAGE_KEY = 'wasd-typing-machine-id';

      
        let machineId = localStorage.getItem(STORAGE_KEY);

        if (!machineId) {
          
            machineId = await generateFingerprint();
            try {
                localStorage.setItem(STORAGE_KEY, machineId);
            } catch (e) {
                console.error('Failed to save machine ID to localStorage:', e);
            }
        }

        return machineId;
    }

  
    async function init() {
        const machineId = await getMachineId();

      
        const originalFetch = window.fetch;
        window.fetch = function(resource, options = {}) {
          
            if (typeof resource === 'string' && resource.includes('/api/')) {
                options.headers = options.headers || {};
                options.headers['X-Machine-ID'] = machineId;
            }
            return originalFetch(resource, options);
        };

      
        window.clientMachineId = machineId;

        console.log('Client machine ID initialized');
    }

  
    init();
})();