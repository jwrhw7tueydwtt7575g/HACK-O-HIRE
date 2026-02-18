import axios from 'axios'

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// SOC Services Base URLs
export const SOC_SERVICES = {
  aiIntelligence: process.env.NEXT_PUBLIC_AI_INTELLIGENCE_URL || 'http://localhost:8001',
  enrichment: process.env.NEXT_PUBLIC_ENRICHMENT_URL || 'http://localhost:8002',
  soar: process.env.NEXT_PUBLIC_SOAR_URL || 'http://localhost:8003',
  opensearch: process.env.NEXT_PUBLIC_OPENSEARCH_URL || 'http://localhost:9200',
  wazuh: process.env.NEXT_PUBLIC_WAZUH_API_URL || 'https://localhost:55000'
}

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
