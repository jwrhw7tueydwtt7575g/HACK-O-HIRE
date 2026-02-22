import axios from 'axios'

// ---------------------------------------------------------------------------
// Resolve SOC service URLs — env vars take priority, then localStorage config
// ---------------------------------------------------------------------------

function getConfig(): Record<string, string> {
  if (typeof window === 'undefined') return {}
  try {
    return JSON.parse(localStorage.getItem('soc_config') || '{}')
  } catch { return {} }
}

function resolveUrl(envKey: string, configKey: string, fallback: string): string {
  if (typeof process !== 'undefined' && process.env[envKey]) return process.env[envKey]!
  const cfg = getConfig()
  return (cfg[configKey] as string) || fallback
}

export const getServiceUrls = () => ({
  aiIntelligence: resolveUrl('NEXT_PUBLIC_AI_INTELLIGENCE_URL', 'ai_url',         'http://localhost:8001'),
  enrichment:     resolveUrl('NEXT_PUBLIC_ENRICHMENT_URL',       'enrichment_url', 'http://localhost:8002'),
  soar:           resolveUrl('NEXT_PUBLIC_SOAR_URL',             'soar_url',       'http://localhost:8003'),
  opensearch:     resolveUrl('NEXT_PUBLIC_OPENSEARCH_URL',       'opensearch_url', 'http://localhost:9200'),
  wazuh:          resolveUrl('NEXT_PUBLIC_WAZUH_API_URL',        'wazuh_url',      'https://localhost:55000'),
  vector:         resolveUrl('NEXT_PUBLIC_VECTOR_URL',           'vector_url',     'http://localhost:8686'),
})

/** @deprecated use getServiceUrls() so settings page changes take effect */
export const SOC_SERVICES = {
  aiIntelligence: process.env.NEXT_PUBLIC_AI_INTELLIGENCE_URL || 'http://localhost:8001',
  enrichment:     process.env.NEXT_PUBLIC_ENRICHMENT_URL       || 'http://localhost:8002',
  soar:           process.env.NEXT_PUBLIC_SOAR_URL             || 'http://localhost:8003',
  opensearch:     process.env.NEXT_PUBLIC_OPENSEARCH_URL       || 'http://localhost:9200',
  wazuh:          process.env.NEXT_PUBLIC_WAZUH_API_URL        || 'https://localhost:55000',
}

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor for adding auth tokens if needed
apiClient.interceptors.request.use(
  (config) => {
    // Add authorization token if available
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for handling errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      console.error('Unauthorized access')
      // Optionally redirect to login
    } else if (error.response?.status === 503) {
      console.error('Service unavailable')
    }
    return Promise.reject(error)
  }
)

export default apiClient
