import landing from './landing'
import common from './common'
import dashboard from './dashboard'
import channelMonitorV2 from './channelMonitorV2'
import admin from './admin'
import misc from './misc'

export default {
  batchImageGuide: {
    title: 'Batch Image Generation',
    description: 'Submit multiple prompts in one job and download the generated images when complete',
  },
  ...landing,
  ...common,
  ...dashboard,
  ...channelMonitorV2,
  admin,
  ...misc,
}
