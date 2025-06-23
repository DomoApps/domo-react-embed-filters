/**
 * Function to process dashboard filters, ensuring the values for 'IN' operators are arrays
 * @param {Array} dashboards - Array of dashboard objects containing filters
 */
const processDashboardFilters = (dashboards) => {
  dashboards.forEach((dashboard) => {
    dashboard.filter.forEach((filter) => {
      if (filter.operator === 'IN' && !Array.isArray(filter.values)) {
        filter.values = [filter.values]
      }
    })
  })
}

export default processDashboardFilters
