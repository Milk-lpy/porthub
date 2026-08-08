import { GraphChart, LineChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { init, use, type ECharts } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'

use([GraphChart, LineChart, GridComponent, TooltipComponent, CanvasRenderer])

export { init }
export type { ECharts }
